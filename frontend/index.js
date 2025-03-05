const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 1778;

app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  try {
    const gameHtml = fs.readFileSync(path.join(__dirname, 'BreakingBadGamev7beta.html'), 'utf8');
    res.send(gameHtml);
  } catch (error) {
    console.error('Error reading game file:', error);
    res.status(500).send('Error loading the game');
  }
});

app.listen(port, () => {
  console.log(`Breaking Bad Game frontend running at http://localhost:${port}`);
}); 