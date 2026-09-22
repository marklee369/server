const http = require('http');
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { ExpressPeerServer } = require('peer');
const { v4: uuidv4 } = require('uuid');
const { Server } = require('socket.io'); 
const { WebSocketServer } = require('ws');
const xss = require('xss');             

const PORT = process.env.PORT || 8080;
const AUTH_KEY = process.env.AUTH_KEY || 'YOUR_SECRET_KEY'; 
const PEER_MOUNT_PATH = normalizePath(process.env.PEER_MOUNT_PATH || '/peerjs');
const PEER_SERVER_PATH = normalizePath(process.env.PEER_SERVER_PATH || '/');
const SOCKET_IO_PATH = normalizePath(process.env.SOCKET_IO_PATH || '/socket.io');
const SOCKET_IO_TRANSPORTS = parseSocketIoTransports(process.env.SOCKET_IO_TRANSPORTS || 'websocket,polling');
const REQUIRE_WEBSOCKET = parseBoolean(process.env.REQUIRE_WEBSOCKET || 'false');
const WEBSOCKET_UPGRADE_TIMEOUT_MS = Number(process.env.WEBSOCKET_UPGRADE_TIMEOUT_MS || 5000);

const ROOM_EMPTY_TIMEOUT_MS = 5 * 60 * 1000; 
const ROOM_HARD_EXPIRATION_MS = 24 * 60 * 60 * 1000; 
const MAX_GLOBAL_ROOMS = 2666;
const MAX_PAYLOAD_SIZE = 1e5; 

const rooms = {};

function normalizePath(path) {
    if (!path || path === '/') return '/';
    return `/${String(path).replace(/^\/+|\/+$/g, '')}`;
}

function buildPeerWsPath(mountPath, serverPath) {
    const base = normalizePath(`${mountPath}${serverPath === '/' ? '' : serverPath}`);
    return `${base === '/' ? '' : base}/peerjs`;
}

function parseSocketIoTransports(value) {
    const allowed = new Set(['websocket', 'polling']);
    const transports = String(value)
        .split(',')
        .map(transport => transport.trim())
        .filter(transport => allowed.has(transport));

    return transports.length ? transports : ['websocket', 'polling'];
}

function parseBoolean(value) {
    return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function getRequestPath(url) {
    try {
        return new URL(url || '/', 'http://localhost').pathname;
    } catch {
        return '/';
    }
}

function createRoutedWebSocketServer({ server, path }) {
    const wss = new WebSocketServer({
        noServer: true,
        perMessageDeflate: false
    });

    server.on('upgrade', (req, socket, head) => {
        if (getRequestPath(req.url) !== path) return;

        wss.handleUpgrade(req, socket, head, (ws) => {
            wss.emit('connection', ws, req);
        });
    });

    return wss;
}

function disableEngineIoCompression(engineSocket) {
    if (!engineSocket || engineSocket.__compressionDisabled) return;

    const originalSendPacket = engineSocket.sendPacket.bind(engineSocket);
    engineSocket.sendPacket = (type, data, options = {}, callback) => {
        if (typeof options === 'function') {
            callback = options;
            options = {};
        }

        return originalSendPacket(type, data, { ...options, compress: false }, callback);
    };

    const originalWrite = engineSocket.write.bind(engineSocket);
    engineSocket.write = (data, options = {}, callback) => {
        if (typeof options === 'function') {
            callback = options;
            options = {};
        }

        return originalWrite(data, { ...options, compress: false }, callback);
    };

    engineSocket.__compressionDisabled = true;
}

function hashPassword(password) {
    if (!password) return '';
    return crypto.createHash('sha256').update(String(password)).digest('hex');
}

const ipCreationCounts = new Map();

function rateLimitMiddleware(req, res, next) {
    const ip = req.ip;
    const now = Date.now();
    
    let userRecords = ipCreationCounts.get(ip) || [];
    userRecords = userRecords.filter(timestamp => now - timestamp < 60 * 60 * 1000);
    
    if (userRecords.length >= 30) {
        return res.status(429).json({ error: '创建房间过于频繁，请稍后再试' });
    }
    
    userRecords.push(now);
    ipCreationCounts.set(ip, userRecords);
    next();
}

setInterval(() => ipCreationCounts.clear(), 2 * 60 * 60 * 1000);

function generateShortCode() {
    return (Math.floor(Math.random() * 900000) + 100000).toString();
}

const app = express();
app.set('trust proxy', true);

const defaultAllowedOrigins = [
    "https://player.arksec.net",
    "https://game.arksec.net"
];

const allowedOrigins = (process.env.CORS_ORIGINS || defaultAllowedOrigins.join(','))
    .split(',')
    .map(origin => origin.trim())
    .filter(Boolean);

const corsOptions = { origin: allowedOrigins, methods: ["GET", "POST"] };

app.use(cors(corsOptions));
app.use(express.json({ limit: '50kb' })); 

app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send('<h1>Nexus Backend is running Securely with Hash Auth</h1>');
});

app.get('/healthz', (req, res) => {
    res.json({
        ok: true,
        uptime: process.uptime(),
        peer: {
            mountPath: PEER_MOUNT_PATH,
            serverPath: PEER_SERVER_PATH,
            websocketPath: buildPeerWsPath(PEER_MOUNT_PATH, PEER_SERVER_PATH)
        },
        socketio: {
            path: SOCKET_IO_PATH,
            transports: SOCKET_IO_TRANSPORTS,
            requireWebsocket: REQUIRE_WEBSOCKET,
            websocketUpgradeTimeoutMs: WEBSOCKET_UPGRADE_TIMEOUT_MS
        }
    });
});

const serverStartTime = process.hrtime.bigint();
app.get('/get-time', (req, res) => {
    const uptimeNanoseconds = process.hrtime.bigint() - serverStartTime;
    res.json({ serverTime: Number(uptimeNanoseconds) / 1e6 });
});

app.post('/register-room', rateLimitMiddleware, (req, res) => {
    if (Object.keys(rooms).length >= MAX_GLOBAL_ROOMS) {
        return res.status(503).json({ error: '服务器房间容量已满，请稍后再试' });
    }

    const { longId, roomPassword } = req.body;
    if (!longId || !roomPassword) return res.status(400).json({ error: '缺少长ID或房间密码' });
    
    let shortCode;
    do { shortCode = generateShortCode(); } while (rooms[shortCode]);

    rooms[shortCode] = { 
        host: longId, 
        pwdHash: hashPassword(roomPassword),
        createdAt: Date.now(),
        emptySince: null,
        activeSockets: new Set()
    };
    res.status(201).json({ shortCode });
});

app.post('/register-player2', (req, res) => {
    const { shortCode, p2_longId, roomPassword } = req.body;
    if (!shortCode || !p2_longId || !roomPassword) return res.status(400).json({ error: '缺少参数' });

    const room = rooms[shortCode];
    if (!room) return res.status(404).json({ error: '未找到房间或房间已被解散' });

    if (room.pwdHash !== hashPassword(roomPassword)) {
        return res.status(401).json({ error: '房间密码错误' });
    }

    const adapterCount = io.sockets.adapter.rooms.get(shortCode)?.size || 0;
    const trackedCount = room.activeSockets.size;
    const activeSocketsCount = Math.max(adapterCount, trackedCount);

    if (activeSocketsCount >= 2) {
        return res.status(409).json({ error: '当前房间已满员 (Max: 2)' }); 
    }

    room.emptySince = null; 
    res.status(200).send();
});

app.get('/get-room/:shortCode', (req, res) => {
    const { shortCode } = req.params;
    const { pwd } = req.query;
    
    const room = rooms[shortCode];
    if (!room) return res.status(404).json({ error: '未找到该房间' });
    
    if (room.pwdHash !== hashPassword(pwd)) {
        return res.status(401).json({ error: '密码错误，拒绝获取房主信令' });
    }

    res.json({ longId: room.host });
});

const server = http.createServer(app);

const io = new Server(server, {
    path: SOCKET_IO_PATH,
    cors: corsOptions,
    transports: SOCKET_IO_TRANSPORTS,
    allowUpgrades: true,
    allowEIO3: false,
    pingTimeout: 60000,
    pingInterval: 25000,
    maxHttpBufferSize: MAX_PAYLOAD_SIZE,
    perMessageDeflate: false, 
    httpCompression: false,
});

io.engine.on('connection_error', (err) => {
    console.warn('[socket.io] connection_error', {
        code: err.code,
        message: err.message,
        context: err.context,
        origin: err.req?.headers?.origin,
        url: err.req?.url,
        forwardedProto: err.req?.headers?.['x-forwarded-proto'],
        forwardedHost: err.req?.headers?.['x-forwarded-host']
    });
});

io.use((socket, next) => {
    disableEngineIoCompression(socket.conn);

    const token = socket.handshake.auth.token || socket.handshake.headers['authorization'];
    if (token === `Bearer ${AUTH_KEY}` || token === AUTH_KEY) return next();
    return next(new Error('Unauthorized: Invalid Server Key'));
});

io.on('connection', (socket) => {
    disableEngineIoCompression(socket.conn);

    console.log('[socket.io] connected', {
        id: socket.id,
        transport: socket.conn.transport.name,
        origin: socket.handshake.headers.origin
    });

    socket.conn.once('upgrade', (transport) => {
        console.log('[socket.io] upgraded', {
            id: socket.id,
            transport: transport.name
        });
    });

    if (REQUIRE_WEBSOCKET && socket.conn.transport.name !== 'websocket') {
        setTimeout(() => {
            if (socket.connected && socket.conn.transport.name !== 'websocket') {
                console.warn('[socket.io] disconnecting non-websocket transport', {
                    id: socket.id,
                    transport: socket.conn.transport.name
                });
                socket.disconnect(true);
            }
        }, WEBSOCKET_UPGRADE_TIMEOUT_MS);
    }

    socket.on('join_room', (data) => {
        if (!data || typeof data !== 'object') return;
        const { shortCode, roomPassword } = data;

        const room = rooms[shortCode];
        if (!room) return;

        if (room.pwdHash !== hashPassword(roomPassword)) {
            return;
        }

        socket.join(shortCode);
        room.activeSockets.add(socket.id);
        room.emptySince = null;

        if (data.peerId) {
            socket.to(shortCode).emit('peer_joined', { peerId: xss(data.peerId) });
        }
    });

    socket.on('chat_message', (data) => {
        const { shortCode, message, senderId } = data;
        if (!shortCode || !message || !socket.rooms.has(shortCode)) return;
        
        const safeMessage = xss(message.trim());
        if (safeMessage) {
            io.compress(false).to(shortCode).emit('chat_message', {
                senderId: xss(senderId),
                message: safeMessage,
                timestamp: Date.now()
            });
        }
    });

    socket.on('media_sync', (data) => {
        const { shortCode, type, action, currentTime, mediaUrl, authPayload, playing } = data;
        if (!shortCode || !socket.rooms.has(shortCode)) return;
        
        socket.compress(false).volatile.to(shortCode).emit('media_sync', {
            type, action, currentTime, playing,
            mediaUrl: mediaUrl ? xss(mediaUrl) : null,
            authPayload: authPayload || null,
            timestamp: Date.now()
        });
    });

    socket.on('game_sync', (data) => {
        const { shortCode, ...payload } = data;
        if (!shortCode || !socket.rooms.has(shortCode)) return;

        socket.compress(false).to(shortCode).emit('game_sync', {
            ...payload,
            timestamp: Date.now()
        });
    });

    socket.on('voice_signal', (data) => {
        const { shortCode } = data;
        if (!shortCode || !socket.rooms.has(shortCode)) return;
        socket.to(shortCode).emit('voice_signal', {
            action: data.action,
            peerId: data.peerId,
            timestamp: Date.now()
        });
    });

    socket.on('screen_share_signal', (data) => {
        const { shortCode } = data;
        if (!shortCode || !socket.rooms.has(shortCode)) return;
        socket.to(shortCode).emit('screen_share_signal', {
            action: data.action,
            peerId: data.peerId,
            timestamp: Date.now()
        });
    });

    socket.on('disconnecting', () => {
        for (const shortCode of socket.rooms) {
            if (rooms[shortCode] && rooms[shortCode].activeSockets) {
                rooms[shortCode].activeSockets.delete(socket.id);
            }
        }
    });
});

const peerServer = ExpressPeerServer(server, {
    debug: false, 
    proxied: true, 
    generateClientId: () => uuidv4(),
    path: PEER_SERVER_PATH,
    corsOptions,
    createWebSocketServer: createRoutedWebSocketServer
});

app.use(PEER_MOUNT_PATH, peerServer);

setInterval(() => {
    const now = Date.now();
    for (const shortCode in rooms) {
        const room = rooms[shortCode];
        
        const adapterCount = io.sockets.adapter.rooms.get(shortCode)?.size || 0;
        const trackedCount = room.activeSockets ? room.activeSockets.size : 0;
        const activeSockets = Math.max(adapterCount, trackedCount);
        
        if (activeSockets === 0) {
            if (!room.emptySince) {
                room.emptySince = now; 
            } else if (now - room.emptySince > ROOM_EMPTY_TIMEOUT_MS) {
                delete rooms[shortCode];
            }
        } else {
            room.emptySince = null; 
        }

        if (rooms[shortCode] && (now - room.createdAt > ROOM_HARD_EXPIRATION_MS)) {
            delete rooms[shortCode];
        }
    }
}, 15 * 1000); 

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on 0.0.0.0:${PORT}`);
    console.log(`PeerJS HTTP base: ${PEER_MOUNT_PATH}${PEER_SERVER_PATH === '/' ? '' : PEER_SERVER_PATH}`);
    console.log(`PeerJS WebSocket path: ${buildPeerWsPath(PEER_MOUNT_PATH, PEER_SERVER_PATH)}`);
    console.log(`Socket.IO path: ${SOCKET_IO_PATH}`);
    console.log(`Socket.IO transports: ${SOCKET_IO_TRANSPORTS.join(',')}`);
    console.log(`Require WebSocket: ${REQUIRE_WEBSOCKET}`);
});
