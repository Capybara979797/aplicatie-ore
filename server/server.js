// Fisier: /server/server.js (Versiunea 4.3 - Corecție Salvare Date)

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

const DB_PATH = path.join(__dirname, 'database.json');
const SECRET_KEY = 'cheia-ta-super-secreta-pe-care-o-vei-schimba';

const ADMIN_USER = "admin";
const ADMIN_PASS = "admin123";

// --- Funcții ajutătoare pentru Baza de Date ---
const readDB = () => {
    if (!fs.existsSync(DB_PATH)) {
        fs.writeFileSync(DB_PATH, JSON.stringify({ users: {}, workData: {} }));
    }
    const data = fs.readFileSync(DB_PATH);
    return JSON.parse(data);
};

const writeDB = (data) => {
    fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
};

// --- Middleware pentru Autentificare ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- Rute API ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { return res.status(400).json({ message: 'Numele de utilizator și parola sunt obligatorii.' }); }
    const db = readDB();
    if (db.users[username]) { return res.status(409).json({ message: 'Numele de utilizator există deja.' }); }
    const hashedPassword = await bcrypt.hash(password, 10);
    db.users[username] = { password: hashedPassword };
    db.workData[username] = {}; // Inițializăm containerul pentru datele de lucru
    writeDB(db);
    io.emit('new_user_registered', { username: username });
    res.status(201).json({ message: 'Utilizator înregistrat cu succes!' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const db = readDB();
    const user = db.users[username];
    if (!user || !(await bcrypt.compare(password, user.password))) { return res.status(401).json({ message: 'Nume de utilizator sau parolă incorectă.' }); }
    const token = jwt.sign({ username: username, isAdmin: false }, SECRET_KEY, { expiresIn: '24h' });
    res.json({ message: 'Login reușit!', token: token });
});

app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USER && password === ADMIN_PASS) {
        const token = jwt.sign({ username: username, isAdmin: true }, SECRET_KEY, { expiresIn: '8h' });
        res.json({ message: 'Autentificare admin reușită!', token: token });
    } else {
        res.status(401).json({ message: 'Credențiale admin incorecte.' });
    }
});

app.get('/api/workdata', authenticateToken, (req, res) => {
    const db = readDB();
    const userData = db.workData[req.user.username] || {};
    res.json(userData);
});

app.post('/api/workdata', authenticateToken, (req, res) => {
    const { date, entries } = req.body;
    if (!date || typeof entries === 'undefined') { return res.status(400).json({ message: 'Datele trimise sunt incomplete.' }); }
    
    const db = readDB();

    // CORECȚIA PRINCIPALĂ: Verificăm dacă există containerul pentru datele utilizatorului. Dacă nu, îl creăm.
    if (!db.workData[req.user.username]) {
        db.workData[req.user.username] = {};
    }

    if (entries.length > 0) {
        db.workData[req.user.username][date] = { entries };
    } else {
        delete db.workData[req.user.username][date];
    }
    
    writeDB(db);
    res.status(200).json({ message: 'Date salvate cu succes!' });
});

app.delete('/api/workdata/:date', authenticateToken, (req, res) => {
    const { date } = req.params;
    const db = readDB();
    if (db.workData[req.user.username] && db.workData[req.user.username][date]) {
        delete db.workData[req.user.username][date];
        writeDB(db);
        res.status(200).json({ message: 'Intrarea a fost ștearsă.' });
    } else {
        res.status(404).json({ message: 'Intrarea nu a fost găsită.' });
    }
});


let onlineUsers = {};
let adminSockets = [];
io.on('connection', (socket) => {
    socket.on('user_online', (data) => {
        try {
            const decoded = jwt.verify(data.token, SECRET_KEY);
            if (decoded.isAdmin) {
                adminSockets.push(socket.id);
                socket.emit('update_online_users', onlineUsers);
            } else if (decoded.username) {
                const username = decoded.username;
                const ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address.replace('::ffff:', '');
                onlineUsers[username] = { socketId: socket.id, ip: ip };
                io.emit('update_online_users', onlineUsers);
            }
        } catch (err) { /* Ignorăm token-urile invalide */ }
    });
    socket.on('admin_get_user_data', (data) => {
        const { username } = data;
        const db = readDB();
        const userData = db.workData[username] || {};
        socket.emit('admin_receive_user_data', { username: username, workData: userData });
    });
    socket.on('send_message_to_user', (data) => {
        const { targetUsername, message } = data;
        const targetUser = onlineUsers[targetUsername];
        if (targetUser) {
            io.to(targetUser.socketId).emit('new_message', { message: message });
        }
    });
    socket.on('disconnect', () => {
        let wasUser = false;
        for (const username in onlineUsers) {
            if (onlineUsers[username].socketId === socket.id) {
                delete onlineUsers[username];
                wasUser = true;
                break;
            }
        }
        adminSockets = adminSockets.filter(id => id !== socket.id);
        if (wasUser) {
            io.emit('update_online_users', onlineUsers);
        }
    });
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Serverul rulează pe http://localhost:${PORT}`);
});