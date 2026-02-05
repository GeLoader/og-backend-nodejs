const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const PDFDocument = require('pdfkit');
const { stringify } = require('csv-stringify/sync');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors({
    origin: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : '*',
    credentials: true
}));

// MySQL connection pool
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'time_tracking',
    port: parseInt(process.env.DB_PORT || '3306'),
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

const SECRET_KEY = process.env.JWT_SECRET || 'your-secret-key-change-in-production-123';
const ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7;

// Middleware: Get current user
const getCurrentUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ detail: 'Not authenticated' });
        }

        const token = authHeader.split(' ')[1];
        const payload = jwt.verify(token, SECRET_KEY);
        const userId = payload.sub;

        const [rows] = await pool.execute('SELECT * FROM users WHERE id = ?', [userId]);
        const user = rows[0];

        if (!user) return res.status(401).json({ detail: 'User not found' });
        if (user.status === 'inactive') return res.status(403).json({ detail: 'Account is inactive' });

        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ detail: 'Invalid or expired token' });
    }
};

const getAdminUser = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ detail: 'Admin access required' });
    next();
};

// --- Routes ---

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const [rows] = await pool.execute('SELECT * FROM users WHERE email = ?', [email]);
    const user = rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ detail: 'Incorrect email or password' });
    }

    const token = jwt.sign({ sub: user.id }, SECRET_KEY, { expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m` });
    const { password: _, ...userWithoutPassword } = user;
    res.json({ token, user: userWithoutPassword });
});

// Projects: List
app.get('/api/projects', getCurrentUser, async (req, res) => {
    const [rows] = await pool.execute('SELECT * FROM projects ORDER BY created_at DESC');
    res.json(rows);
});

// Projects: Create
app.post('/api/projects', getCurrentUser, getAdminUser, async (req, res) => {
    const { name, description } = req.body;
    const id = uuidv4();
    const created_by = req.user.id;
    
    await pool.execute(
        'INSERT INTO projects (id, name, description, created_by) VALUES (?, ?, ?, ?)',
        [id, name, description, created_by]
    );
    
    res.json({ id, name, description, created_by, status: 'active' });
});

// Time Entries: List
app.get('/api/time-entries', getCurrentUser, async (req, res) => {
    const { start_date, end_date, user_id } = req.query;
    let query = 'SELECT * FROM time_entries WHERE 1=1';
    const params = [];

    if (req.user.role === 'employee') {
        query += ' AND user_id = ?';
        params.push(req.user.id);
    } else if (user_id) {
        query += ' AND user_id = ?';
        params.push(user_id);
    }

    if (start_date) {
        query += ' AND date >= ?';
        params.push(start_date);
    }
    if (end_date) {
        query += ' AND date <= ?';
        params.push(end_date);
    }

    query += ' ORDER BY start_time DESC';
    const [rows] = await pool.execute(query, params);
    res.json(rows);
});

// Time Entries: Manual Create
app.post('/api/time-entries/manual', getCurrentUser, async (req, res) => {
    const { project_id, task_id, start_time, end_time, duration, notes } = req.body;
    if (!end_time) return res.status(400).json({ detail: 'End time required' });

    const id = uuidv4();
    const user_id = req.user.id;
    const start = new Date(start_time);
    const end = new Date(end_time);
    const calcDuration = duration || Math.floor((end - start) / 1000);
    const date = start.toISOString().split('T')[0];

    await pool.execute(
        'INSERT INTO time_entries (id, user_id, project_id, task_id, start_time, end_time, duration, entry_type, date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [id, user_id, project_id, task_id, start, end, calcDuration, 'manual', date, notes]
    );

    res.json({ id, user_id, project_id, task_id, start_time, end_time, duration: calcDuration, entry_type: 'manual', date, notes });
});

// Timer: Start
app.post('/api/timer/start', getCurrentUser, async (req, res) => {
    const { project_id, task_id } = req.body;
    const user_id = req.user.id;

    // Deactivate old timers
    await pool.execute('UPDATE timer_sessions SET is_active = FALSE WHERE user_id = ?', [user_id]);

    const id = uuidv4();
    const now = new Date();
    const date = now.toISOString().split('T')[0];

    await pool.execute(
        'INSERT INTO timer_sessions (id, user_id, project_id, task_id, start_time, last_heartbeat, is_active, date) VALUES (?, ?, ?, ?, ?, ?, TRUE, ?)',
        [id, user_id, project_id, task_id, now, now, date]
    );

    res.json({ id, user_id, project_id, task_id, start_time: now, date });
});

// Timer: Stop
app.post('/api/timer/stop', getCurrentUser, async (req, res) => {
    const { notes } = req.body;
    const user_id = req.user.id;

    const [rows] = await pool.execute('SELECT * FROM timer_sessions WHERE user_id = ? AND is_active = TRUE LIMIT 1', [user_id]);
    const timer = rows[0];

    if (!timer) return res.status(404).json({ detail: 'No active timer' });

    const end = new Date();
    const duration = Math.floor((end - new Date(timer.start_time)) / 1000);
    const entryId = uuidv4();

    // Move to time_entries
    await pool.execute(
        'INSERT INTO time_entries (id, user_id, project_id, task_id, start_time, end_time, duration, entry_type, date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, "timer", ?, ?)',
        [entryId, user_id, timer.project_id, timer.task_id, timer.start_time, end, duration, timer.date, notes]
    );

    // Stop session
    await pool.execute('UPDATE timer_sessions SET is_active = FALSE WHERE id = ?', [timer.id]);

    res.json({ id: entryId, duration, status: 'stopped' });
});

// --- Server Init ---

const initDefaultUsers = async () => {
    const [rows] = await pool.execute('SELECT id FROM users WHERE role = "admin" LIMIT 1');
    if (rows.length === 0) {
        const id = uuidv4();
        const hashedPassword = await bcrypt.hash('admin123', 10);
        await pool.execute(
            'INSERT INTO users (id, email, name, password, role, status) VALUES (?, ?, ?, ?, "admin", "active")',
            [id, 'admin@omnigratum.com', 'Admin User', hashedPassword]
        );
        console.log('Default admin created: admin@omnigratum.com / admin123');
    }
};

const PORT = process.env.PORT || 8000;
app.listen(PORT, async () => {
    try {
        await initDefaultUsers();
        console.log(`Server running on port ${PORT}`);
    } catch (err) {
        console.error('Startup error:', err);
    }
});
