const fs = require('fs');
const path = require('path');

const inputLocation = process.argv[2];
const outputLocation = process.argv[3];

const input = require(path.join(process.cwd(), inputLocation));

const output = input.songs.map(({ title, artist, album, episode, id, url }) => ({
    title,
    artist,
    release: album,
    episode,
    id,
    url,
    meta: '{}'
}))
fs.writeFileSync(path.join(process.cwd(), outputLocation), JSON.stringify(output, null, 4), 'utf8');