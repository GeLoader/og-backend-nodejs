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
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: parseInt(process.env.DB_PORT),
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

// Auth: Get current user
app.get('/api/auth/me', getCurrentUser, (req, res) => {
    const { password: _, ...userWithoutPassword } = req.user;
    res.json(userWithoutPassword);
});

// Auth: Change Password
app.put('/api/auth/change-password', getCurrentUser, async (req, res) => {
    try {
        const { new_password } = req.body;

        if (!new_password || new_password.length < 6) {
            return res.status(400).json({ detail: 'Password must be at least 6 characters' });
        }

        const hashedPassword = await bcrypt.hash(new_password, 10);
        await pool.execute(
            'UPDATE users SET password = ? WHERE id = ?',
            [hashedPassword, req.user.id]
        );

        res.json({ success: true, message: 'Password changed successfully' });
    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ detail: 'Failed to change password' });
    }
});

// NEW: Get User Time Tracking Settings
app.get('/api/user/time-tracking-settings', getCurrentUser, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            'SELECT first_day_of_week, working_on_weekends FROM users WHERE id = ?',
            [req.user.id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ detail: 'User not found' });
        }

        const settings = rows[0];
        res.json({
            first_day_of_week: settings.first_day_of_week || 'monday',
            working_on_weekends: settings.working_on_weekends || false
        });
    } catch (error) {
        console.error('Get time tracking settings error:', error);
        res.status(500).json({ detail: 'Failed to get time tracking settings' });
    }
});

// NEW: Update User Time Tracking Settings
app.put('/api/user/time-tracking-settings', getCurrentUser, async (req, res) => {
    try {
        const { first_day_of_week, working_on_weekends } = req.body;

        // Validate first_day_of_week
        const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
        if (first_day_of_week && !validDays.includes(first_day_of_week.toLowerCase())) {
            return res.status(400).json({ detail: 'Invalid day of week' });
        }

        await pool.execute(
            'UPDATE users SET first_day_of_week = ?, working_on_weekends = ? WHERE id = ?',
            [first_day_of_week || 'monday', working_on_weekends || false, req.user.id]
        );

        res.json({
            success: true,
            message: 'Time tracking settings updated',
            first_day_of_week: first_day_of_week || 'monday',
            working_on_weekends: working_on_weekends || false
        });
    } catch (error) {
        console.error('Update time tracking settings error:', error);
        res.status(500).json({ detail: 'Failed to update time tracking settings' });
    }
});

// Users: List (Admin)
app.get('/api/users', getCurrentUser, getAdminUser, async (req, res) => {
    const [rows] = await pool.execute('SELECT id, email, name, role, status, created_at FROM users');
    res.json(rows);
});

// Employees: List (Admin) - UPDATED to include project count and daily_hours
app.get('/api/admin/employees', getCurrentUser, getAdminUser, async (req, res) => {
    const { status } = req.query;
    let query = `
        SELECT
            u.id,
            u.email,
            u.name,
            u.role,
            u.status,
            u.default_project,
            u.default_task,
            u.daily_hours,
            u.created_at,
            COUNT(DISTINCT up.project_id) as project_count
        FROM users u
        LEFT JOIN user_projects up ON u.id = up.user_id
        WHERE u.role = "employee"`;

    const params = [];

    if (status && status !== 'all') {
        query += ' AND u.status = ?';
        params.push(status);
    }

    query += ' GROUP BY u.id, u.email, u.name, u.role, u.status, u.default_project, u.default_task, u.daily_hours, u.created_at';
    query += ' ORDER BY u.created_at DESC';

    const [rows] = await pool.execute(query, params);
    res.json(rows);
});

// Employees: Create (Admin) - UPDATED to include daily_hours
app.post('/api/admin/employees', getCurrentUser, getAdminUser, async (req, res) => {
    const { name, email, password, status, default_project, default_task, daily_hours } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ detail: 'Name, email, and password are required' });
    }

    const id = uuidv4();
    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await pool.execute(
            'INSERT INTO users (id, email, name, password, role, status, default_project, default_task, daily_hours) VALUES (?, ?, ?, ?, "employee", ?, ?, ?, ?)',
            [id, email, name, hashedPassword, status || 'active', default_project || null, default_task || null, daily_hours || 8.0]
        );

        res.json({ id, email, name, role: 'employee', status: status || 'active', daily_hours: daily_hours || 8.0, created_at: new Date() });
    } catch (error) {
        console.error('Create employee error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ detail: 'Email already exists' });
        }
        res.status(500).json({ detail: 'Failed to create employee: ' + error.message });
    }
});

// Employees: Update (Admin) - UPDATED to include daily_hours
app.put('/api/admin/employees/:id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;
    const { name, email, password, status, default_project, default_task, daily_hours } = req.body;

    try {
        // Get current user data to handle missing fields in partial updates
        const [currentRows] = await pool.execute('SELECT * FROM users WHERE id = ?', [id]);
        if (currentRows.length === 0) return res.status(404).json({ detail: 'User not found' });
        const currentUser = currentRows[0];

        const updateName = name !== undefined ? name : currentUser.name;
        const updateEmail = email !== undefined ? email : currentUser.email;
        const updateStatus = status !== undefined ? status : currentUser.status;
        const updateProject = default_project !== undefined ? default_project : currentUser.default_project;
        const updateTask = default_task !== undefined ? default_task : currentUser.default_task;
        const updateDailyHours = daily_hours !== undefined ? daily_hours : currentUser.daily_hours;

        if (password) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await pool.execute(
                'UPDATE users SET name = ?, email = ?, password = ?, status = ?, default_project = ?, default_task = ?, daily_hours = ? WHERE id = ?',
                [updateName, updateEmail, hashedPassword, updateStatus, updateProject || null, updateTask || null, updateDailyHours, id]
            );
        } else {
            await pool.execute(
                'UPDATE users SET name = ?, email = ?, status = ?, default_project = ?, default_task = ?, daily_hours = ? WHERE id = ?',
                [updateName, updateEmail, updateStatus, updateProject || null, updateTask || null, updateDailyHours, id]
            );
        }

        res.json({ id, name: updateName, email: updateEmail, role: 'employee', status: updateStatus, daily_hours: updateDailyHours });
    } catch (error) {
        console.error('Update employee error:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ detail: 'Email already exists' });
        }
        res.status(500).json({ detail: 'Failed to update employee: ' + error.message });
    }
});

// Employees: Delete (Admin)
app.delete('/api/admin/employees/:id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.execute('DELETE FROM users WHERE id = ? AND role = "employee"', [id]);
        res.json({ success: true, message: 'Employee deleted' });
    } catch (error) {
        res.status(500).json({ detail: 'Failed to delete employee' });
    }
});

// NEW: Get assigned projects for an employee
app.get('/api/admin/employees/:id/projects', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;

    try {
        const [rows] = await pool.execute(
            `SELECT p.id, p.name, p.description, up.assigned_at
             FROM user_projects up
             JOIN projects p ON up.project_id = p.id
             WHERE up.user_id = ?
             ORDER BY up.assigned_at DESC`,
            [id]
        );
        res.json(rows);
    } catch (error) {
        console.error('Get employee projects error:', error);
        res.status(500).json({ detail: 'Failed to get employee projects' });
    }
});

// NEW: Assign multiple projects to an employee
app.post('/api/admin/employees/:id/projects/assign', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;
    const { project_ids } = req.body;

    if (!Array.isArray(project_ids)) {
        return res.status(400).json({ detail: 'project_ids must be an array' });
    }

    try {
        // First, remove all existing assignments
        await pool.execute('DELETE FROM user_projects WHERE user_id = ?', [id]);

        // Then add new assignments
        if (project_ids.length > 0) {
            const values = project_ids.map(project_id => [uuidv4(), id, project_id, new Date()]);
            const placeholders = values.map(() => '(?, ?, ?, ?)').join(', ');
            const flatValues = values.flat();

            await pool.execute(
                `INSERT INTO user_projects (id, user_id, project_id, assigned_at) VALUES ${placeholders}`,
                flatValues
            );
        }

        res.json({ success: true, message: 'Projects assigned successfully', count: project_ids.length });
    } catch (error) {
        console.error('Assign projects error:', error);
        res.status(500).json({ detail: 'Failed to assign projects: ' + error.message });
    }
});

// NEW: Remove a project assignment from an employee
app.delete('/api/admin/employees/:id/projects/:project_id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id, project_id } = req.params;

    try {
        await pool.execute(
            'DELETE FROM user_projects WHERE user_id = ? AND project_id = ?',
            [id, project_id]
        );
        res.json({ success: true, message: 'Project assignment removed' });
    } catch (error) {
        console.error('Remove project assignment error:', error);
        res.status(500).json({ detail: 'Failed to remove project assignment' });
    }
});

// Projects: List
app.get('/api/projects', getCurrentUser, async (req, res) => {
    const [rows] = await pool.execute('SELECT * FROM projects ORDER BY created_at DESC');
    res.json(rows);
});

// Projects: Create (Admin)
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

// Projects: Update (Admin)
app.put('/api/projects/:id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;
    const { name, description, status } = req.body;

    await pool.execute(
        'UPDATE projects SET name = ?, description = ?, status = ? WHERE id = ?',
        [name, description, status || 'active', id]
    );

    res.json({ id, name, description, status: status || 'active' });
});

// Projects: Delete (Admin)
app.delete('/api/projects/:id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;

    // Optional: Check if there are tasks or time entries associated with this project
    // For now, simple delete
    await pool.execute('DELETE FROM projects WHERE id = ?', [id]);

    res.json({ success: true, message: 'Project deleted' });
});

// Tasks: List
app.get('/api/tasks', getCurrentUser, async (req, res) => {
    const { project_id } = req.query;
    let query = 'SELECT * FROM tasks';
    const params = [];
    if (project_id) {
        query += ' WHERE project_id = ?';
        params.push(project_id);
    }
    query += ' ORDER BY created_at DESC';
    const [rows] = await pool.execute(query, params);
    res.json(rows);
});

// Tasks: Create (Admin)
app.post('/api/tasks', getCurrentUser, getAdminUser, async (req, res) => {
    const { name, description, project_id } = req.body;
    const id = uuidv4();
    await pool.execute(
        'INSERT INTO tasks (id, name, description, project_id) VALUES (?, ?, ?, ?)',
        [id, name, description, project_id]
    );
    res.json({ id, name, description, project_id, status: 'active' });
});

// Tasks: Update (Admin)
app.put('/api/tasks/:id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;
    const { name, description, project_id, status } = req.body;

    await pool.execute(
        'UPDATE tasks SET name = ?, description = ?, project_id = ?, status = ? WHERE id = ?',
        [name, description, project_id, status || 'active', id]
    );

    res.json({ id, name, description, project_id, status: status || 'active' });
});

// Tasks: Delete (Admin)
app.delete('/api/tasks/:id', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;
    await pool.execute('DELETE FROM tasks WHERE id = ?', [id]);
    res.json({ success: true, message: 'Task deleted' });
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
        'INSERT INTO time_entries (id, user_id, project_id, task_id, start_time, end_time, duration, entry_type, date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, "manual", ?, ?)',
        [id, user_id, project_id, task_id, start, end, calcDuration, date, notes]
    );

    // AUTO-CREATE/UPDATE DRAFT TIMESHEET
    await updateOrCreateDraftTimesheet(user_id, date);

    res.json({ id, user_id, project_id, task_id, start_time, end_time, duration: calcDuration, entry_type: 'manual', date, notes });
});

// Time Entries: Update (Edit) - UPDATED to also update timesheets table
app.put('/api/time-entries/:id', getCurrentUser, async (req, res) => {
    const { id } = req.params;
    const { project_id, task_id, start_time, end_time, notes } = req.body;

    try {
        // Get existing entry
        const [entryRows] = await pool.execute('SELECT * FROM time_entries WHERE id = ?', [id]);

        if (entryRows.length === 0) {
            return res.status(404).json({ detail: 'Time entry not found' });
        }

        const entry = entryRows[0];

        // Check authorization - employees can only edit their own, admins can edit any
        if (req.user.role === 'employee' && entry.user_id !== req.user.id) {
            return res.status(403).json({ detail: 'Unauthorized' });
        }

        // Calculate new duration
        const start = new Date(start_time);
        const end = new Date(end_time);
        const duration = Math.floor((end - start) / 1000);
        const date = start.toISOString().split('T')[0];

        // 1. UPDATE TIME_ENTRIES TABLE
        await pool.execute(
            'UPDATE time_entries SET project_id = ?, task_id = ?, start_time = ?, end_time = ?, duration = ?, date = ?, notes = ? WHERE id = ?',
            [project_id, task_id, start, end, duration, date, notes || null, id]
        );

        // 2. UPDATE TIMESHEETS TABLE
        await updateOrCreateDraftTimesheet(entry.user_id, date);

        res.json({
            id,
            user_id: entry.user_id,
            project_id,
            task_id,
            start_time,
            end_time,
            duration,
            date,
            notes
        });
    } catch (error) {
        console.error('Update time entry error:', error);
        res.status(500).json({ detail: 'Failed to update time entry: ' + error.message });
    }
});

// Time Entries: Delete
app.delete('/api/time-entries/:id', getCurrentUser, async (req, res) => {
    const { id } = req.params;
    const user_id = req.user.id;
    const role = req.user.role;

    try {
        // Get the entry first to get the date for timesheet update
        const [entryRows] = await pool.execute('SELECT * FROM time_entries WHERE id = ?', [id]);

        if (entryRows.length === 0) {
            return res.status(404).json({ detail: 'Time entry not found' });
        }

        const entry = entryRows[0];

        // Employees can only delete their own entries, admins can delete any
        let query = 'DELETE FROM time_entries WHERE id = ?';
        const params = [id];

        if (role === 'employee') {
            query += ' AND user_id = ?';
            params.push(user_id);
        }

        const [result] = await pool.execute(query, params);

        if (result.affectedRows === 0) {
            return res.status(404).json({ detail: 'Time entry not found or unauthorized' });
        }

        // Update the related timesheet
        await updateOrCreateDraftTimesheet(entry.user_id, entry.date);

        res.json({ success: true, message: 'Time entry deleted' });
    } catch (error) {
        console.error('Delete time entry error:', error);
        res.status(500).json({ detail: 'Failed to delete time entry' });
    }
});

// Timer: Get Active Timer
app.get('/api/timer/active', getCurrentUser, async (req, res) => {
    const user_id = req.user.id;

    try {
        const [rows] = await pool.execute(
            'SELECT * FROM timer_sessions WHERE user_id = ? AND is_active = TRUE LIMIT 1',
            [user_id]
        );

        if (rows.length === 0) {
            return res.json(null);
        }

        res.json(rows[0]);
    } catch (error) {
        console.error('Get active timer error:', error);
        res.status(500).json({ detail: 'Failed to get active timer' });
    }
});

// Timer: Start
app.post('/api/timer/start', getCurrentUser, async (req, res) => {
    const { project_id, task_id } = req.body;
    const user_id = req.user.id;

    try {
        // Check if there's already an active timer
        const [activeRows] = await pool.execute(
            'SELECT * FROM timer_sessions WHERE user_id = ? AND is_active = TRUE',
            [user_id]
        );

        if (activeRows.length > 0) {
            return res.status(400).json({ detail: 'Timer already running' });
        }

        const id = uuidv4();
        const start_time = new Date();
        const date = start_time.toISOString().split('T')[0];

        await pool.execute(
            'INSERT INTO timer_sessions (id, user_id, project_id, task_id, start_time, last_heartbeat, is_active, date) VALUES (?, ?, ?, ?, ?, ?, TRUE, ?)',
            [id, user_id, project_id || null, task_id || null, start_time, start_time, date]
        );

        res.json({
            id,
            user_id,
            project_id,
            task_id,
            start_time,
            is_active: true,
            date
        });
    } catch (error) {
        console.error('Start timer error:', error);
        res.status(500).json({ detail: 'Failed to start timer' });
    }
});

// Timer: Stop
app.post('/api/timer/stop', getCurrentUser, async (req, res) => {
    const user_id = req.user.id;

    try {
        // Get active timer
        const [rows] = await pool.execute(
            'SELECT * FROM timer_sessions WHERE user_id = ? AND is_active = TRUE',
            [user_id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ detail: 'No active timer found' });
        }

        const timer = rows[0];
        const end_time = new Date();
        const duration = Math.floor((end_time - new Date(timer.start_time)) / 1000);

        // Create time entry
        const entryId = uuidv4();
        await pool.execute(
            'INSERT INTO time_entries (id, user_id, project_id, task_id, start_time, end_time, duration, entry_type, date) VALUES (?, ?, ?, ?, ?, ?, ?, "timer", ?)',
            [entryId, user_id, timer.project_id, timer.task_id, timer.start_time, end_time, duration, timer.date]
        );

        // Deactivate timer
        await pool.execute(
            'UPDATE timer_sessions SET is_active = FALSE WHERE id = ?',
            [timer.id]
        );

        // AUTO-CREATE/UPDATE DRAFT TIMESHEET
        await updateOrCreateDraftTimesheet(user_id, timer.date);

        res.json({
            time_entry_id: entryId,
            duration,
            start_time: timer.start_time,
            end_time
        });
    } catch (error) {
        console.error('Stop timer error:', error);
        res.status(500).json({ detail: 'Failed to stop timer' });
    }
});

// Timer: Heartbeat (keep alive)
app.post('/api/timer/heartbeat', getCurrentUser, async (req, res) => {
    const user_id = req.user.id;

    try {
        await pool.execute(
            'UPDATE timer_sessions SET last_heartbeat = ? WHERE user_id = ? AND is_active = TRUE',
            [new Date(), user_id]
        );

        res.json({ success: true });
    } catch (error) {
        console.error('Timer heartbeat error:', error);
        res.status(500).json({ detail: 'Failed to update heartbeat' });
    }
});

// Timesheets: List - MODIFIED to compute total_hours from duration column
app.get('/api/timesheets', getCurrentUser, async (req, res) => {
    const { status } = req.query;
    let query = 'SELECT *, ROUND(duration / 3600, 2) as total_hours FROM timesheets WHERE 1=1';
    const params = [];

    if (req.user.role === 'employee') {
        query += ' AND user_id = ?';
        params.push(req.user.id);
    }

    if (status) {
        query += ' AND status = ?';
        params.push(status);
    }

    query += ' ORDER BY week_start DESC';
    const [rows] = await pool.execute(query, params);
    res.json(rows);
});

// Timesheets: Get Entries for a Timesheet
app.get('/api/timesheets/:id/entries', getCurrentUser, async (req, res) => {
    const { id } = req.params;

    try {
        // Get timesheet to verify access
        const [timesheetRows] = await pool.execute(
            'SELECT * FROM timesheets WHERE id = ?',
            [id]
        );

        if (timesheetRows.length === 0) {
            return res.status(404).json({ detail: 'Timesheet not found' });
        }

        const timesheet = timesheetRows[0];

        // Check authorization - employees can only view their own
        if (req.user.role === 'employee' && timesheet.user_id !== req.user.id) {
            return res.status(403).json({ detail: 'Unauthorized' });
        }

        // Get time entries for this timesheet's week
        const [entries] = await pool.execute(
            'SELECT * FROM time_entries WHERE user_id = ? AND date >= ? AND date <= ? ORDER BY date ASC, start_time ASC',
            [timesheet.user_id, timesheet.week_start, timesheet.week_end]
        );

        res.json(entries);
    } catch (error) {
        console.error('Get timesheet entries error:', error);
        res.status(500).json({ detail: 'Failed to get timesheet entries' });
    }
});

// Timesheets: Submit
app.post('/api/timesheets/submit', getCurrentUser, async (req, res) => {
    const { timesheet_id } = req.body;

    try {
        // Get timesheet
        const [timesheetRows] = await pool.execute(
            'SELECT * FROM timesheets WHERE id = ?',
            [timesheet_id]
        );

        if (timesheetRows.length === 0) {
            return res.status(404).json({ detail: 'Timesheet not found' });
        }

        const timesheet = timesheetRows[0];

        // Check authorization
        if (req.user.role === 'employee' && timesheet.user_id !== req.user.id) {
            return res.status(403).json({ detail: 'Unauthorized' });
        }

        // Only allow submitting draft timesheets
        if (timesheet.status !== 'draft') {
            return res.status(400).json({ detail: 'Only draft timesheets can be submitted' });
        }

        // Update status to submitted
        await pool.execute(
            'UPDATE timesheets SET status = ?, submitted_at = ? WHERE id = ?',
            ['submitted', new Date(), timesheet_id]
        );

        res.json({ success: true, message: 'Timesheet submitted for review' });
    } catch (error) {
        console.error('Submit timesheet error:', error);
        res.status(500).json({ detail: 'Failed to submit timesheet' });
    }
});

// Timesheets: Reopen
app.put('/api/timesheets/:id/reopen', getCurrentUser, async (req, res) => {
    const { id } = req.params;

    try {
        // Get timesheet
        const [timesheetRows] = await pool.execute(
            'SELECT * FROM timesheets WHERE id = ?',
            [id]
        );

        if (timesheetRows.length === 0) {
            return res.status(404).json({ detail: 'Timesheet not found' });
        }

        const timesheet = timesheetRows[0];

        // Check authorization - employees can only reopen their own
        if (req.user.role === 'employee' && timesheet.user_id !== req.user.id) {
            return res.status(403).json({ detail: 'Unauthorized' });
        }

        // Only allow reopening if status is approved or denied
        if (timesheet.status !== 'approved' && timesheet.status !== 'denied') {
            return res.status(400).json({ detail: 'Can only reopen approved or denied timesheets' });
        }

        // Reopen timesheet
        await pool.execute(
            'UPDATE timesheets SET status = ?, submitted_at = NULL, reviewed_at = NULL, reviewed_by = NULL WHERE id = ?',
            ['draft', id]
        );

        res.json({ success: true, message: 'Timesheet reopened' });
    } catch (error) {
        console.error('Reopen timesheet error:', error);
        res.status(500).json({ detail: 'Failed to reopen timesheet' });
    }
});

// Timesheets: Review (Approve/Deny) - ADMIN ONLY
app.put('/api/timesheets/:id/review', getCurrentUser, getAdminUser, async (req, res) => {
    const { id } = req.params;
    const { status, admin_comment } = req.body;

    try {
        // Validate status
        if (!['approved', 'denied'].includes(status)) {
            return res.status(400).json({ detail: 'Status must be "approved" or "denied"' });
        }

        // Get timesheet
        const [timesheetRows] = await pool.execute(
            'SELECT * FROM timesheets WHERE id = ?',
            [id]
        );

        if (timesheetRows.length === 0) {
            return res.status(404).json({ detail: 'Timesheet not found' });
        }

        const timesheet = timesheetRows[0];

        // Only allow reviewing submitted timesheets
        if (timesheet.status !== 'submitted') {
            return res.status(400).json({ detail: 'Only submitted timesheets can be reviewed' });
        }

        // Update timesheet status
        await pool.execute(
            'UPDATE timesheets SET status = ?, admin_comment = ?, reviewed_at = ?, reviewed_by = ? WHERE id = ?',
            [status, admin_comment || null, new Date(), req.user.id, id]
        );

        // Create notification for employee
        const dateRange = formatDateRange(timesheet.week_start, timesheet.week_end);
        await createNotification(
            timesheet.user_id,
            `Timesheet ${status}`,
            `Your timesheet for ${dateRange} has been ${status}${admin_comment ? ': ' + admin_comment : ''}`,
            'timesheet_review'
        );

        res.json({ success: true, message: `Timesheet ${status}` });
    } catch (error) {
        console.error('Review timesheet error:', error);
        res.status(500).json({ detail: 'Failed to review timesheet' });
    }
});

// Notifications: List
app.get('/api/notifications', getCurrentUser, async (req, res) => {
    const [rows] = await pool.execute('SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
    // Map is_read to read for frontend compatibility
    const notifications = rows.map(n => ({
        ...n,
        read: n.is_read
    }));
    res.json(notifications);
});

// Notifications: Get Unread Count
app.get('/api/notifications/unread-count', getCurrentUser, async (req, res) => {
    try {
        const [[result]] = await pool.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = FALSE',
            [req.user.id]
        );
        res.json({ count: result.count || 0 });
    } catch (error) {
        console.error('Get unread count error:', error);
        res.status(500).json({ detail: 'Failed to get unread count' });
    }
});

// Notifications: Mark as Read
app.put('/api/notifications/:id/read', getCurrentUser, async (req, res) => {
    const { id } = req.params;

    try {
        await pool.execute(
            'UPDATE notifications SET is_read = TRUE WHERE id = ? AND user_id = ?',
            [id, req.user.id]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Mark notification read error:', error);
        res.status(500).json({ detail: 'Failed to mark notification as read' });
    }
});

// Notifications: Mark All as Read
app.put('/api/notifications/mark-all-read', getCurrentUser, async (req, res) => {
    try {
        await pool.execute(
            'UPDATE notifications SET is_read = TRUE WHERE user_id = ?',
            [req.user.id]
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Mark all notifications read error:', error);
        res.status(500).json({ detail: 'Failed to mark all notifications as read' });
    }
});

// Dashboard: Stats
app.get('/api/dashboard/stats', getCurrentUser, async (req, res) => {
    if (req.user.role === 'admin') {
        const [[{ total_employees }]] = await pool.execute('SELECT COUNT(*) as total_employees FROM users WHERE role = "employee"');
        const [[{ active_employees }]] = await pool.execute('SELECT COUNT(*) as active_employees FROM users WHERE role = "employee" AND status = "active"');
        const [[{ pending_timesheets }]] = await pool.execute('SELECT COUNT(*) as pending_timesheets FROM timesheets WHERE status = "submitted"');
        const [[{ total_projects }]] = await pool.execute('SELECT COUNT(*) as total_projects FROM projects');
        const [[{ active_timers }]] = await pool.execute('SELECT COUNT(*) as active_timers FROM timer_sessions WHERE is_active = TRUE');

        res.json({
            total_employees,
            active_employees,
            pending_timesheets,
            total_projects,
            active_timers
        });
    } else {
        const today = new Date().toISOString().split('T')[0];
        const [[{ today_seconds }]] = await pool.execute('SELECT SUM(duration) as today_seconds FROM time_entries WHERE user_id = ? AND date = ?', [req.user.id, today]);
        res.json({
            today_hours: Math.round((today_seconds || 0) / 3600 * 100) / 100
        });
    }
});

// Reports: Generate Time Report
app.get('/api/reports/time', getCurrentUser, async (req, res) => {
    try {
        const { start_date, end_date, group_by, user_id, project_id } = req.query;

        if (!start_date || !end_date) {
            return res.status(400).json({ detail: 'start_date and end_date are required' });
        }

        // Build query based on group_by parameter
        let query = '';
        let params = [];

        // Base query parts
        const baseFrom = `FROM time_entries te
            LEFT JOIN users u ON te.user_id = u.id
            LEFT JOIN projects p ON te.project_id = p.id
            LEFT JOIN tasks t ON te.task_id = t.id
            WHERE te.date >= ? AND te.date <= ?`;

        params.push(start_date, end_date);

        // Add filters
        if (req.user.role === 'employee') {
            query = baseFrom + ' AND te.user_id = ?';
            params.push(req.user.id);
        } else if (user_id) {
            query = baseFrom + ' AND te.user_id = ?';
            params.push(user_id);
        } else {
            query = baseFrom;
        }

        if (project_id) {
            query += ' AND te.project_id = ?';
            params.push(project_id);
        }

        // Group by logic
        let selectClause = '';
        let groupByClause = '';

        switch (group_by) {
            case 'user':
                selectClause = `u.id, u.name as label,
                    ROUND(SUM(te.duration) / 3600, 2) as total_hours,
                    COUNT(te.id) as entry_count`;
                groupByClause = 'GROUP BY u.id, u.name';
                break;
            case 'project':
                selectClause = `p.id, p.name as label,
                    ROUND(SUM(te.duration) / 3600, 2) as total_hours,
                    COUNT(te.id) as entry_count`;
                groupByClause = 'GROUP BY p.id, p.name';
                break;
            case 'task':
                selectClause = `t.id, t.name as label,
                    ROUND(SUM(te.duration) / 3600, 2) as total_hours,
                    COUNT(te.id) as entry_count`;
                groupByClause = 'GROUP BY t.id, t.name';
                break;
            case 'date':
            default:
                selectClause = `te.date as id, te.date as label,
                    ROUND(SUM(te.duration) / 3600, 2) as total_hours,
                    COUNT(te.id) as entry_count`;
                groupByClause = 'GROUP BY te.date';
                break;
        }

        const fullQuery = `SELECT ${selectClause} ${query} ${groupByClause} ORDER BY label`;

        const [rows] = await pool.execute(fullQuery, params);

        // Calculate summary
        const total_hours = rows.reduce((sum, row) => sum + parseFloat(row.total_hours || 0), 0);
        const total_entries = rows.reduce((sum, row) => sum + parseInt(row.entry_count || 0), 0);

        res.json({
            data: rows,
            summary: {
                total_hours: Math.round(total_hours * 100) / 100,
                total_entries: total_entries
            },
            filters: {
                start_date,
                end_date,
                group_by: group_by || 'date',
                user_id: user_id || null,
                project_id: project_id || null
            }
        });
    } catch (error) {
        console.error('Generate report error:', error);
        res.status(500).json({ detail: 'Failed to generate report: ' + error.message });
    }
});

// Reports: Export PDF - UPDATED with proper filtering
app.get('/api/reports/export/pdf', getCurrentUser, async (req, res) => {
    try {
        const { start_date, end_date, user_id, project_id } = req.query;

        if (!start_date || !end_date) {
            return res.status(400).json({ detail: 'start_date and end_date are required' });
        }

        // Build query with joins to get approval status from timesheets
        let query = `
            SELECT 
                te.*,
                u.name as user_name,
                u.email as user_email,
                p.name as project_name,
                t.name as task_name,
                ts.status as approval_status
            FROM time_entries te
            LEFT JOIN users u ON te.user_id = u.id
            LEFT JOIN projects p ON te.project_id = p.id
            LEFT JOIN tasks t ON te.task_id = t.id
            LEFT JOIN timesheets ts ON (
                te.user_id = ts.user_id 
                AND te.date >= ts.week_start 
                AND te.date <= ts.week_end
            )
            WHERE te.date >= ? AND te.date <= ?`;

        const params = [start_date, end_date];

        // Filter based on user role
        if (req.user.role === 'employee') {
            query += ' AND te.user_id = ?';
            params.push(req.user.id);
        } else if (user_id && user_id !== 'all') {
            query += ' AND te.user_id = ?';
            params.push(user_id);
        }

        // Apply project filter
        if (project_id && project_id !== 'all') {
            query += ' AND te.project_id = ?';
            params.push(project_id);
        }

        query += ' ORDER BY te.date DESC, te.start_time DESC';

        const [entries] = await pool.execute(query, params);

        // Create PDF
        const doc = new PDFDocument({ margin: 50, size: 'A4' });

        // Set response headers
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="detailed_report_${start_date}_${end_date}.pdf"`);

        // Pipe PDF to response
        doc.pipe(res);

        // Add header
        doc.fontSize(16).font('Helvetica-Bold').text('DETAILED REPORT', { align: 'center' });
        doc.moveDown();

        // Format dates for display
        const startDateObj = new Date(start_date);
        const endDateObj = new Date(end_date);
        const dateOptions = { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' };
        const formattedStart = startDateObj.toLocaleDateString('en-US', dateOptions);
        const formattedEnd = endDateObj.toLocaleDateString('en-US', dateOptions);

        doc.fontSize(12).font('Helvetica').fillColor('#666')
            .text(`Time frame: ${formattedStart} - ${formattedEnd}`, { align: 'left' });
        doc.moveDown();

        // Calculate totals
        const totalSeconds = entries.reduce((sum, e) => sum + (e.duration || 0), 0);
        const hours = Math.floor(totalSeconds / 3600);
        const minutes = Math.floor((totalSeconds % 3600) / 60);
        const seconds = totalSeconds % 60;
        const totalHoursStr = `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;

        doc.fontSize(12).font('Helvetica-Bold').fillColor('#000')
            .text(`Total hours: ${totalHoursStr}`);
        doc.moveDown(2);

        // Group entries by date
        const groupedByDate = {};
        entries.forEach(entry => {
            if (!groupedByDate[entry.date]) {
                groupedByDate[entry.date] = [];
            }
            groupedByDate[entry.date].push(entry);
        });

        // Add table header styling
        doc.fontSize(10).font('Helvetica-Bold').fillColor('#666');
        const tableTop = doc.y;
        const columnWidths = { user: 100, project: 150, hours: 80, status: 100 };
        const startX = 50;

        doc.text('USER', startX, tableTop, { width: columnWidths.user });
        doc.text('PROJECT', startX + columnWidths.user, tableTop, { width: columnWidths.project });
        doc.text('TOTAL HOURS', startX + columnWidths.user + columnWidths.project, tableTop, { width: columnWidths.hours, align: 'right' });
        doc.text('APPROVAL STATUS', startX + columnWidths.user + columnWidths.project + columnWidths.hours, tableTop, { width: columnWidths.status, align: 'center' });

        doc.moveTo(startX, doc.y + 5).lineTo(550, doc.y + 5).stroke();
        doc.moveDown();

        // Add entries grouped by date
        Object.keys(groupedByDate).sort((a, b) => new Date(b) - new Date(a)).forEach(date => {
            const dateEntries = groupedByDate[date];
            const dateObj = new Date(date);
            const formattedDate = dateObj.toLocaleDateString('en-US', dateOptions);

            // Date header with gray background
            const dateY = doc.y;
            doc.rect(startX - 5, dateY, 500, 20).fillAndStroke('#f0f0f0', '#ccc');
            doc.fontSize(11).font('Helvetica-Bold').fillColor('#000');
            doc.text(formattedDate, startX, dateY + 5);

            // Calculate date total
            const dateTotalSeconds = dateEntries.reduce((sum, e) => sum + (e.duration || 0), 0);
            const dateHours = Math.floor(dateTotalSeconds / 3600);
            const dateMinutes = Math.floor((dateTotalSeconds % 3600) / 60);
            const dateSeconds = dateTotalSeconds % 60;
            const dateTotalStr = `${dateHours}:${String(dateMinutes).padStart(2, '0')}:${String(dateSeconds).padStart(2, '0')}`;

            doc.text(dateTotalStr, startX + columnWidths.user + columnWidths.project, dateY + 5, { width: columnWidths.hours, align: 'right' });
            doc.moveDown(1.5);

            // Add each entry for this date
            dateEntries.forEach(entry => {
                const y = doc.y;
                doc.fontSize(9).font('Helvetica').fillColor('#000');

                doc.text(entry.user_name || 'N/A', startX, y, { width: columnWidths.user });
                doc.text(entry.project_name || 'No Project', startX + columnWidths.user, y, { width: columnWidths.project });

                const entryHours = Math.floor((entry.duration || 0) / 3600);
                const entryMinutes = Math.floor(((entry.duration || 0) % 3600) / 60);
                const entrySeconds = (entry.duration || 0) % 60;
                const entryTimeStr = `${entryHours}:${String(entryMinutes).padStart(2, '0')}:${String(entrySeconds).padStart(2, '0')}`;

                doc.text(entryTimeStr, startX + columnWidths.user + columnWidths.project, y, { width: columnWidths.hours, align: 'right' });

                // Status badge
                const status = entry.approval_status || 'draft';
                doc.text(status.charAt(0).toUpperCase() + status.slice(1), startX + columnWidths.user + columnWidths.project + columnWidths.hours, y, { width: columnWidths.status, align: 'center' });

                doc.moveDown(0.8);

                // Add new page if needed
                if (doc.y > 700) {
                    doc.addPage();
                }
            });

            doc.moveDown(0.5);
        });

        // Add footer with total
        doc.moveDown();
        doc.moveTo(startX, doc.y).lineTo(550, doc.y).stroke();
        doc.moveDown();
        doc.fontSize(12).font('Helvetica-Bold').fillColor('#000');
        doc.text('TOTAL', startX, doc.y);
        doc.text(totalHoursStr, startX + columnWidths.user + columnWidths.project, doc.y, { width: columnWidths.hours, align: 'right', continued: false });

        doc.end();
    } catch (error) {
        console.error('Export PDF error:', error);
        if (!res.headersSent) {
            res.status(500).json({ detail: 'Failed to export PDF: ' + error.message });
        }
    }
});

// Reports: Export CSV
app.get('/api/reports/export/csv', getCurrentUser, async (req, res) => {
    try {
        const { start_date, end_date, user_id } = req.query;

        if (!start_date || !end_date) {
            return res.status(400).json({ detail: 'start_date and end_date are required' });
        }

        // Get time entries data
        let query = `SELECT te.date, te.start_time, te.end_time, te.duration, te.notes,
            u.name as user_name, u.email as user_email,
            p.name as project_name, t.name as task_name
            FROM time_entries te
            LEFT JOIN users u ON te.user_id = u.id
            LEFT JOIN projects p ON te.project_id = p.id
            LEFT JOIN tasks t ON te.task_id = t.id
            WHERE te.date >= ? AND te.date <= ?`;

        const params = [start_date, end_date];

        if (req.user.role === 'employee') {
            query += ' AND te.user_id = ?';
            params.push(req.user.id);
        } else if (user_id) {
            query += ' AND te.user_id = ?';
            params.push(user_id);
        }

        query += ' ORDER BY te.date DESC, te.start_time DESC';

        const [entries] = await pool.execute(query, params);

        // Convert to CSV format
        const csvData = entries.map(entry => ({
            Date: new Date(entry.date).toLocaleDateString(),
            Employee: entry.user_name || 'N/A',
            Email: entry.user_email || 'N/A',
            Project: entry.project_name || 'No Project',
            Task: entry.task_name || 'No Task',
            'Start Time': new Date(entry.start_time).toLocaleTimeString(),
            'End Time': new Date(entry.end_time).toLocaleTimeString(),
            'Hours': Math.round((entry.duration / 3600) * 100) / 100,
            Notes: entry.notes || ''
        }));

        const csv = stringify(csvData, {
            header: true,
            columns: ['Date', 'Employee', 'Email', 'Project', 'Task', 'Start Time', 'End Time', 'Hours', 'Notes']
        });

        // Set response headers
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=time_report_${start_date}_${end_date}.csv`);

        res.send(csv);
    } catch (error) {
        console.error('Export CSV error:', error);
        res.status(500).json({ detail: 'Failed to export CSV: ' + error.message });
    }
});

// --- Helper Functions ---

// FIXED: Helper function to calculate week start and end based on first_day_of_week setting
function getWeekBounds(dateString, firstDayOfWeek = 'monday') {
    const date = new Date(dateString);
    const currentDay = date.getDay(); // 0 = Sunday, 1 = Monday, ..., 6 = Saturday

    // Map first_day_of_week string to day number
    const dayMap = {
        'sunday': 0,
        'monday': 1,
        'tuesday': 2,
        'wednesday': 3,
        'thursday': 4,
        'friday': 5,
        'saturday': 6
    };

    const targetDay = dayMap[firstDayOfWeek.toLowerCase()] || 1; // Default to Monday if invalid

    // Calculate how many days to go back to reach the week start
    let diff = currentDay - targetDay;
    if (diff < 0) {
        diff += 7; // If we're before the target day, go back to previous week
    }

    // Calculate week_start
    const weekStart = new Date(date);
    weekStart.setDate(date.getDate() - diff);

    // Calculate week_end (6 days after week_start)
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6);

    return {
        week_start: weekStart.toISOString().split('T')[0],
        week_end: weekEnd.toISOString().split('T')[0]
    };
}

// UPDATED: Helper function to update or create draft timesheet - updates BOTH duration and total_hours
async function updateOrCreateDraftTimesheet(userId, entryDate) {
    try {
        // Fetch user's first_day_of_week setting
        const [userRows] = await pool.execute(
            'SELECT first_day_of_week FROM users WHERE id = ?',
            [userId]
        );

        const firstDayOfWeek = userRows.length > 0 && userRows[0].first_day_of_week
            ? userRows[0].first_day_of_week
            : 'monday';

        // Calculate week bounds using user's setting
        const { week_start, week_end } = getWeekBounds(entryDate, firstDayOfWeek);

        // Check if timesheet exists for this week
        const [existingRows] = await pool.execute(
            'SELECT * FROM timesheets WHERE user_id = ? AND week_start = ? AND week_end = ?',
            [userId, week_start, week_end]
        );

        // Calculate total duration in seconds from all time entries in this week
        const [[{ total_seconds }]] = await pool.execute(
            'SELECT COALESCE(SUM(duration), 0) as total_seconds FROM time_entries WHERE user_id = ? AND date >= ? AND date <= ?',
            [userId, week_start, week_end]
        );
        const duration = total_seconds || 0;
        const total_hours = duration / 3600; // Convert seconds to hours

        if (existingRows.length > 0) {
            const timesheet = existingRows[0];
            // Only update if status is draft
            if (timesheet.status === 'draft') {
                await pool.execute(
                    'UPDATE timesheets SET duration = ?, total_hours = ? WHERE id = ?',
                    [duration, total_hours, timesheet.id]
                );
                console.log(`✅ Updated draft timesheet ${timesheet.id} for week ${week_start} to ${week_end} (${firstDayOfWeek} start) with ${Math.round(total_hours * 100) / 100} hours`);
            }
        } else {
            // Create new draft timesheet
            const timesheetId = uuidv4();
            await pool.execute(
                'INSERT INTO timesheets (id, user_id, week_start, week_end, duration, total_hours, status) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [timesheetId, userId, week_start, week_end, duration, total_hours, 'draft']
            );
            console.log(`✅ Created draft timesheet ${timesheetId} for week ${week_start} to ${week_end} (${firstDayOfWeek} start) with ${Math.round(total_hours * 100) / 100} hours`);
        }
    } catch (error) {
        console.error('❌ Error updating/creating draft timesheet:', error);
        // Don't throw error - this is a background operation
    }
}

// Helper function: Format date range for notifications
function formatDateRange(startDate, endDate) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    const start = new Date(startDate);
    const end = new Date(endDate);

    const formattedStart = start.toLocaleDateString('en-US', options);
    const formattedEnd = end.toLocaleDateString('en-US', options);

    return `${formattedStart} - ${formattedEnd}`;
}

// Helper function: Create notification
async function createNotification(userId, title, message, type = 'info') {
    try {
        const id = uuidv4();
        await pool.execute(
            'INSERT INTO notifications (id, user_id, title, message, type, is_read) VALUES (?, ?, ?, ?, ?, FALSE)',
            [id, userId, title, message, type]
        );
        console.log(`Created notification for user ${userId}: ${title}`);
    } catch (error) {
        console.error('Error creating notification:', error);
        // Don't throw error - this is a background operation
    }
}



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
        console.log(`✅ Server running on port ${PORT}`);
        console.log(`✅ Time entries edit now updates BOTH time_entries and timesheets tables`);
    } catch (err) {
        console.error('Startup error:', err);
    }
});
