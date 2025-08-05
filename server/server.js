// Fisier: /server/server.js (Versiunea 5.1 - FĂRĂ DUPLICATE)

const express = require('express');
const http = require('http');
const { Server } = require("socket.io");
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// --- 1. Configurarea Serverului ---
const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

app.use(cors());
app.use(express.json());

// --- 2. Conectarea la MongoDB Atlas ---
// !!! ASIGURĂ-TE CĂ AI ÎNLOCUIT AICI CU LINK-UL TĂU REAL ȘI PAROLA CORECTĂ !!!
const connectionString = "mongodb+srv://user_aplicatie:suntsmecher1@cluster0.4mwkvog.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

const client = new MongoClient(connectionString, {
    serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});
let db;

async function connectToDatabase() {
    try {
        await client.connect();
        db = client.db("WorkAppData");
        console.log("Conectat cu succes la MongoDB Atlas!");
    } catch (err) {
        console.error("Eroare la conectarea cu MongoDB:", err);
        process.exit(1);
    }
}

const SECRET_KEY = 'cheia-ta-super-secreta-pe-care-o-vei-schimba';
const ADMIN_USER = "admin";
const ADMIN_PASS = "admin123";

// --- 3. Middleware pentru Autentificare ---
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

// --- 4. Rute API pentru HTTP ---
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) { return res.status(400).json({ message: 'Numele de utilizator și parola sunt obligatorii.' }); }
    const usersCollection = db.collection('users');
    const existingUser = await usersCollection.findOne({ username: username });
    if (existingUser) { return res.status(409).json({ message: 'Numele de utilizator există deja.' }); }
    const hashedPassword = await bcrypt.hash(password, 10);
    await usersCollection.insertOne({ username, password: hashedPassword });
    io.emit('new_user_registered', { username: username });
    res.status(201).json({ message: 'Utilizator înregistrat cu succes!' });
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.collection('users').findOne({ username });
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

app.get('/api/workdata', authenticateToken, async (req, res) => {
    const workDataCollection = db.collection('workdata');
    const userData = await workDataCollection.findOne({ username: req.user.username });
    res.json(userData ? userData.data : {});
});

app.post('/api/workdata', authenticateToken, async (req, res) => {
    const { date, entries } = req.body;
    const workDataCollection = db.collection('workdata');
    const username = req.user.username;
    const updateField = `data.${date}`;
    if (entries.length > 0) {
        await workDataCollection.updateOne({ username: username }, { $set: { [updateField]: { entries } } }, { upsert: true });
    } else {
        await workDataCollection.updateOne({ username: username }, { $unset: { [updateField]: "" } });
    }
    res.status(200).json({ message: 'Date salvate cu succes!' });
});

app.delete('/api/workdata/:date', authenticateToken, async (req, res) => {
    const { date } = req.params;
    const workDataCollection = db.collection('workdata');
    const username = req.user.username;
    const updateField = `data.${date}`;
    await workDataCollection.updateOne({ username: username }, { $unset: { [updateField]: "" } });
    res.status(200).json({ message: 'Intrarea a fost ștearsă.' });
});

// --- 5. Logica pentru comunicare în timp real (Socket.IO) ---
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

    socket.on('admin_get_user_data', async (data) => {
        const { username } = data;
        const userData = await db.collection('workdata').findOne({ username: username });
        socket.emit('admin_receive_user_data', { username: username, workData: userData ? userData.data : {} });
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
        for (const username in onlineUsers) { if (onlineUsers[username].socketId === socket.id) { delete onlineUsers[username]; wasUser = true; break; } }
        adminSockets = adminSockets.filter(id => id !== socket.id);
        if (wasUser) { io.emit('update_online_users', onlineUsers); }
    });
});

// --- 6. Pornirea Serverului ---
const PORT = 3000;
connectToDatabase().then(() => {
    server.listen(PORT, () => {
        console.log(`Serverul rulează pe http://localhost:${PORT}`);
    });
});