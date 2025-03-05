const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const path = require('path');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 1777;

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Enable CORS for the frontend
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// Database setup
const dbPath = path.join(__dirname, 'data', 'breakingbad.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // Sessions table for cookie auth
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        token TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    // Saved games table
    db.run(`CREATE TABLE IF NOT EXISTS saved_games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        game_state TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    // PvP stats table
    db.run(`CREATE TABLE IF NOT EXISTS pvp_stats (
        user_id INTEGER PRIMARY KEY,
        wins INTEGER DEFAULT 0,
        losses INTEGER DEFAULT 0,
        reputation INTEGER DEFAULT 100,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);
    
    // PvP challenges table
    db.run(`CREATE TABLE IF NOT EXISTS pvp_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        challenger_id INTEGER,
        opponent_id INTEGER,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        battle_result TEXT,
        FOREIGN KEY (challenger_id) REFERENCES users (id),
        FOREIGN KEY (opponent_id) REFERENCES users (id)
    )`);
});

// API Routes
app.post('/api/signup', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password are required' });
    }
    
    // Check if username exists
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.json({ success: false, message: 'Database error' });
        }
        
        if (row) {
            return res.json({ success: false, message: 'Username already exists' });
        }
        
        // Hash password
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                return res.json({ success: false, message: 'Error hashing password' });
            }
            
            // Insert new user
            db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], function(err) {
                if (err) {
                    return res.json({ success: false, message: 'Error creating user' });
                }
                
                const userId = this.lastID;
                
                // Create PvP stats entry
                db.run('INSERT INTO pvp_stats (user_id) VALUES (?)', [userId], (err) => {
                    if (err) {
                        return res.json({ success: false, message: 'Error creating PvP stats' });
                    }
                    
                    res.json({ success: true });
                });
            });
        });
    });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.json({ success: false, message: 'Username and password are required' });
    }
    
    db.get('SELECT id, password FROM users WHERE username = ?', [username], (err, row) => {
        if (err) {
            return res.json({ success: false, message: 'Database error' });
        }
        
        if (!row) {
            return res.json({ success: false, message: 'Invalid username or password' });
        }
        
        bcrypt.compare(password, row.password, (err, result) => {
            if (err || !result) {
                return res.json({ success: false, message: 'Invalid username or password' });
            }
            
            // Generate session token
            const token = crypto.randomBytes(64).toString('hex');
            const expires = new Date();
            expires.setDate(expires.getDate() + 30); // Token valid for 30 days
            
            // Store token in database
            db.run('INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)', 
                [row.id, token, expires.toISOString()], function(err) {
                if (err) {
                    return res.json({ success: false, message: 'Error creating session' });
                }
                
                // Set cookie
                res.cookie('bb_session', token, { 
                    expires: expires,
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'lax'
                });
                
                res.json({ success: true, userId: row.id, username: username });
            });
        });
    });
});

app.get('/api/verifySession', (req, res) => {
    const token = req.cookies.bb_session;
    
    if (!token) {
        return res.json({ success: false, message: 'No session found' });
    }
    
    db.get(`
        SELECT s.id, s.user_id, u.username 
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND s.expires_at > datetime('now')
    `, [token], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'Invalid or expired session' });
        }
        
        res.json({ success: true, userId: row.user_id, username: row.username });
    });
});

app.post('/api/logout', (req, res) => {
    const token = req.cookies.bb_session;
    
    if (token) {
        // Remove session from database
        db.run('DELETE FROM sessions WHERE token = ?', [token]);
        
        // Clear cookie
        res.clearCookie('bb_session');
    }
    
    res.json({ success: true });
});

app.get('/api/savedGames', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get saved games
        db.all('SELECT id, name, created_at as date FROM saved_games WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
            if (err) {
                return res.json({ success: false, message: 'Error fetching saved games' });
            }
            
            res.json({ success: true, savedGames: rows });
        });
    });
});

app.post('/api/saveGame', (req, res) => {
    const { username, saveName, gameState } = req.body;
    
    if (!username || !gameState) {
        return res.json({ success: false, message: 'Missing required fields' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Check if user already has a save
        db.get('SELECT id FROM saved_games WHERE user_id = ?', [userId], (err, saveRow) => {
            if (saveRow) {
                // Update existing save - remove updated_at field which doesn't exist
                db.run('UPDATE saved_games SET game_state = ? WHERE id = ?', 
                    [JSON.stringify(gameState), saveRow.id], 
                    function(err) {
                        if (err) {
                            return res.json({ success: false, message: 'Error updating save' });
                        }
                        
                        res.json({ success: true, saveId: saveRow.id });
                    }
                );
            } else {
                // Create new save
                db.run('INSERT INTO saved_games (user_id, name, game_state) VALUES (?, ?, ?)', 
                    [userId, saveName || 'AutoSave', JSON.stringify(gameState)], 
                    function(err) {
                        if (err) {
                            return res.json({ success: false, message: 'Error saving game' });
                        }
                        
                        res.json({ success: true, saveId: this.lastID });
                    }
                );
            }
        });
    });
});

app.get('/api/loadGame', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get the user's save game
        db.get('SELECT id, name, game_state FROM saved_games WHERE user_id = ?', [userId], (err, saveRow) => {
            if (err) {
                return res.json({ success: false, message: 'Error loading game' });
            }
            
            if (!saveRow) {
                return res.json({ success: false, message: 'No saved game found' });
            }
            
            res.json({ 
                success: true, 
                saveId: saveRow.id, 
                saveName: saveRow.name, 
                gameState: JSON.parse(saveRow.game_state)
            });
        });
    });
});

app.get('/api/pvpStats', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get PvP stats
        db.get('SELECT wins, losses, reputation FROM pvp_stats WHERE user_id = ?', [userId], (err, row) => {
            if (err || !row) {
                return res.json({ success: false, message: 'Stats not found' });
            }
            
            res.json({ success: true, stats: row });
        });
    });
});

app.get('/api/pvpOpponents', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get opponents
        db.all(`
            SELECT u.username, p.reputation 
            FROM users u 
            JOIN pvp_stats p ON u.id = p.user_id 
            WHERE u.id != ? 
            ORDER BY p.reputation DESC
        `, [userId], (err, rows) => {
            if (err) {
                return res.json({ success: false, message: 'Error fetching opponents' });
            }
            
            res.json({ success: true, opponents: rows });
        });
    });
});

app.post('/api/createPvPChallenge', (req, res) => {
    const { username, opponent } = req.body;
    
    if (!username || !opponent) {
        return res.json({ success: false, message: 'Missing required fields' });
    }
    
    // Get user IDs
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, challengerRow) => {
        if (err || !challengerRow) {
            return res.json({ success: false, message: 'Challenger not found' });
        }
        
        const challengerId = challengerRow.id;
        
        db.get('SELECT id FROM users WHERE username = ?', [opponent], (err, opponentRow) => {
            if (err || !opponentRow) {
                return res.json({ success: false, message: 'Opponent not found' });
            }
            
            const opponentId = opponentRow.id;
            
            // Check if there's already a pending challenge
            db.get('SELECT id FROM pvp_challenges WHERE challenger_id = ? AND opponent_id = ? AND status = "pending"', 
                [challengerId, opponentId], (err, row) => {
                if (row) {
                    return res.json({ success: false, message: 'Challenge already pending' });
                }
                
                // Create challenge
                db.run('INSERT INTO pvp_challenges (challenger_id, opponent_id) VALUES (?, ?)', 
                    [challengerId, opponentId], function(err) {
                    if (err) {
                        return res.json({ success: false, message: 'Error creating challenge' });
                    }
                    
                    res.json({ success: true, challengeId: this.lastID });
                });
            });
        });
    });
});

app.get('/api/pendingChallenges', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get pending challenges
        db.all(`
            SELECT c.id, u.username AS challenger 
            FROM pvp_challenges c 
            JOIN users u ON c.challenger_id = u.id 
            WHERE c.opponent_id = ? AND c.status = "pending"
        `, [userId], (err, rows) => {
            if (err) {
                return res.json({ success: false, message: 'Error fetching challenges' });
            }
            
            res.json({ success: true, challenges: rows });
        });
    });
});

app.post('/api/respondToChallenge', (req, res) => {
    const { username, challengeId, accept } = req.body;
    
    if (!username || !challengeId || accept === undefined) {
        return res.json({ success: false, message: 'Missing required fields' });
    }
    
    // Update challenge status
    db.run('UPDATE pvp_challenges SET status = ? WHERE id = ?', 
        [accept ? 'accepted' : 'rejected', challengeId], function(err) {
        if (err) {
            return res.json({ success: false, message: 'Error updating challenge' });
        }
        
        res.json({ success: true, accepted: accept });
    });
});

app.post('/api/pvpBattle', (req, res) => {
    const { username, challengeId, gameState } = req.body;
    
    if (!username || !challengeId || !gameState) {
        return res.json({ success: false, message: 'Missing required fields' });
    }
    
    // Verify challenge is accepted
    db.get(`
        SELECT c.id, c.challenger_id, c.opponent_id, uc.username AS challenger, uo.username AS opponent
        FROM pvp_challenges c
        JOIN users uc ON c.challenger_id = uc.id
        JOIN users uo ON c.opponent_id = uo.id
        WHERE c.id = ? AND c.status = "accepted"
    `, [challengeId], (err, challenge) => {
        if (err || !challenge) {
            return res.json({ success: false, message: 'Challenge not found or not accepted' });
        }
        
        // Get user ID
        db.get('SELECT id FROM users WHERE username = ?', [username], (err, player) => {
            if (err || !player) {
                return res.json({ success: false, message: 'Player not found' });
            }
            
            // Verify player is part of the challenge
            if (player.id !== challenge.challenger_id && player.id !== challenge.opponent_id) {
                return res.json({ success: false, message: 'You are not part of this challenge' });
            }
            
            // Determine if player is challenger or opponent
            const isChallenger = player.id === challenge.challenger_id;
            const opponentId = isChallenger ? challenge.opponent_id : challenge.challenger_id;
            const opponentUsername = isChallenger ? challenge.opponent : challenge.challenger;
            
            // Get opponent's game
            db.get('SELECT game_state FROM saved_games WHERE user_id = ?', [opponentId], (err, gameRow) => {
                if (err || !gameRow) {
                    return res.json({ success: false, message: 'Opponent has no saved game' });
                }
                
                const opponentGameState = JSON.parse(gameRow.game_state);
                
                // Calculate battle strengths
                const playerStrength = calculateBattleStrength(gameState);
                const opponentStrength = calculateBattleStrength(opponentGameState);
                
                let playerWon = playerStrength > opponentStrength;
                let reward = Math.floor(opponentStrength * 100);
                let loss = Math.floor(playerStrength * 50);
                
                // Apply battle results to both game states
                if (playerWon) {
                    // Player wins
                    gameState.money += reward;
                    opponentGameState.money = Math.max(0, opponentGameState.money - loss);
                    
                    // Update stats
                    db.run('UPDATE pvp_stats SET wins = wins + 1, reputation = reputation + 10 WHERE user_id = ?', [player.id]);
                    db.run('UPDATE pvp_stats SET losses = losses + 1, reputation = MAX(0, reputation - 5) WHERE user_id = ?', [opponentId]);
                } else {
                    // Opponent wins
                    gameState.money = Math.max(0, gameState.money - loss);
                    opponentGameState.money += reward;
                    
                    // Update stats
                    db.run('UPDATE pvp_stats SET losses = losses + 1, reputation = MAX(0, reputation - 5) WHERE user_id = ?', [player.id]);
                    db.run('UPDATE pvp_stats SET wins = wins + 1, reputation = reputation + 10 WHERE user_id = ?', [opponentId]);
                }
                
                // Store battle result
                const result = {
                    player: username,
                    opponent: opponentUsername,
                    playerStrength: playerStrength,
                    opponentStrength: opponentStrength,
                    playerWon: playerWon,
                    reward: reward,
                    loss: loss,
                    timestamp: new Date().toISOString()
                };
                
                // Update challenge with battle result
                db.run('UPDATE pvp_challenges SET status = "completed", battle_result = ? WHERE id = ?', 
                    [JSON.stringify(result), challengeId]);
                
                // Save both players' game states
                db.get('SELECT id FROM saved_games WHERE user_id = ?', [player.id], (err, playerSaveRow) => {
                    if (playerSaveRow) {
                        db.run('UPDATE saved_games SET game_state = ? WHERE id = ?', 
                            [JSON.stringify(gameState), playerSaveRow.id]);
                    }
                });
                
                db.get('SELECT id FROM saved_games WHERE user_id = ?', [opponentId], (err, opponentSaveRow) => {
                    if (opponentSaveRow) {
                        db.run('UPDATE saved_games SET game_state = ? WHERE id = ?', 
                            [JSON.stringify(opponentGameState), opponentSaveRow.id]);
                    }
                });
                
                res.json({
                    success: true,
                    result: result
                });
            });
        });
    });
});

app.get('/api/battleResults', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get recent battle results
        db.all(`
            SELECT c.battle_result, c.created_at
            FROM pvp_challenges c
            WHERE (c.challenger_id = ? OR c.opponent_id = ?) 
                AND c.status = "completed"
                AND c.battle_result IS NOT NULL
            ORDER BY c.created_at DESC
            LIMIT 10
        `, [userId, userId], (err, rows) => {
            if (err) {
                return res.json({ success: false, message: 'Error fetching results' });
            }
            
            const results = rows.map(row => {
                const result = JSON.parse(row.battle_result);
                result.date = row.created_at;
                return result;
            });
            
            res.json({ success: true, results: results });
        });
    });
});

// Add a new endpoint to check for completed challenges
app.get('/api/completedChallenges', (req, res) => {
    const { username } = req.query;
    
    if (!username) {
        return res.json({ success: false, message: 'Username is required' });
    }
    
    // Get user ID
    db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'User not found' });
        }
        
        const userId = row.id;
        
        // Get recently completed challenges created by this user
        db.all(`
            SELECT c.id, c.battle_result, uo.username AS opponent
            FROM pvp_challenges c
            JOIN users uo ON c.opponent_id = uo.id
            WHERE c.challenger_id = ? 
              AND c.status = 'completed'
              AND c.battle_result IS NOT NULL
              AND c.created_at > datetime('now', '-5 minute')
            ORDER BY c.created_at DESC
        `, [userId], (err, rows) => {
            if (err) {
                return res.json({ success: false, message: 'Error fetching challenges' });
            }
            
            // Convert battle_result from JSON string to object
            const completedChallenges = rows.map(row => {
                return {
                    id: row.id,
                    opponent: row.opponent,
                    result: JSON.parse(row.battle_result)
                };
            });
            
            res.json({ success: true, challenges: completedChallenges });
        });
    });
});

// Add endpoint to check challenge status
app.get('/api/challengeStatus', (req, res) => {
    const { challengeId } = req.query;
    
    if (!challengeId) {
        return res.json({ success: false, message: 'Challenge ID is required' });
    }
    
    db.get('SELECT status FROM pvp_challenges WHERE id = ?', [challengeId], (err, row) => {
        if (err || !row) {
            return res.json({ success: false, message: 'Challenge not found' });
        }
        
        res.json({ success: true, status: row.status });
    });
});

// Add endpoint to get specific challenge result
app.get('/api/challengeResult', (req, res) => {
    const { challengeId } = req.query;
    
    if (!challengeId) {
        return res.json({ success: false, message: 'Challenge ID is required' });
    }
    
    db.get('SELECT battle_result FROM pvp_challenges WHERE id = ? AND status = "completed"', 
        [challengeId], (err, row) => {
        if (err || !row || !row.battle_result) {
            return res.json({ success: false, message: 'Battle result not found' });
        }
        
        res.json({ success: true, result: JSON.parse(row.battle_result) });
    });
});

// Helper function to calculate battle strength
function calculateBattleStrength(state) {
    const characters = {
        Walter: { cookingSkill: 0.7, sellBonus: 1.0, weaponSkill: 0.8 },
        Jesse: { cookingSkill: 0.4, sellBonus: 1.2, weaponSkill: 0.5 }
    };
    
    return state.money * 0.001 + 
           state.meth * state.quality * 0.5 + 
           state.weapons * characters[state.character].weaponSkill * 2 + 
           state.equipmentLevel * 0.5 + 
           (state.saulHired ? 1 : 0) + 
           (state.mikeHired ? 2 : 0) + 
           state.defeatedVillains.length * 0.5;
}

// Serve the main HTML file
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'BreakingBadGamev7beta.html'));
});

// Start server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
}); 