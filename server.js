const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taskflow_secret_key_2024';

// ---- DATABASE SETUP ----
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Initialize tables
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'member',
      must_change_password BOOLEAN DEFAULT false,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_by TEXT REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      assigned_to TEXT REFERENCES users(id),
      priority TEXT DEFAULT 'medium',
      status TEXT DEFAULT 'todo',
      due_date TEXT,
      created_by TEXT REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS project_members (
      id TEXT PRIMARY KEY,
      project_id TEXT REFERENCES projects(id) ON DELETE CASCADE,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      role TEXT DEFAULT 'member',
      UNIQUE(project_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS reset_links (
      token TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ
    );
  `);
  console.log('Database initialized');
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---- HELPERS ----
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ---- AUTH ROUTES ----
app.post('/api/signup', [
  body('name').trim().notEmpty().withMessage('Name is required'),
  body('email').isEmail().withMessage('Valid email required'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, email, password, role } = req.body;

  const existing = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (existing.rows.length) return res.status(400).json({ error: 'Email already in use' });

  const hashed = await bcrypt.hash(password, 10);
  const id = generateId();
  const userRole = role === 'admin' ? 'admin' : 'member';

  await pool.query(
    'INSERT INTO users (id, name, email, password, role) VALUES ($1,$2,$3,$4,$5)',
    [id, name, email, hashed, userRole]
  );

  const token = jwt.sign({ id, email, name, role: userRole }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id, name, email, role: userRole } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const result = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
  const user = result.rows[0];
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
    mustChangePassword: !!user.must_change_password
  });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT id, name, email, role FROM users WHERE id=$1', [req.user.id]);
  if (!result.rows.length) return res.status(404).json({ error: 'User not found' });
  res.json(result.rows[0]);
});

// ---- USERS ----
app.get('/api/users', authMiddleware, async (req, res) => {
  const result = await pool.query(
    'SELECT id, name, email, role, must_change_password, created_at FROM users ORDER BY created_at'
  );
  res.json(result.rows.map(u => ({ ...u, mustChangePassword: !!u.must_change_password })));
});

// Admin: create member with temp password
app.post('/api/admin/create-member', authMiddleware, adminOnly, async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });

  const existing = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (existing.rows.length) return res.status(400).json({ error: 'Email already in use' });

  const tempPassword = 'TF-' + Math.random().toString(36).substr(2, 6).toUpperCase();
  const hashed = await bcrypt.hash(tempPassword, 10);
  const id = generateId();

  await pool.query(
    'INSERT INTO users (id, name, email, password, role, must_change_password) VALUES ($1,$2,$3,$4,$5,$6)',
    [id, name, email, hashed, 'member', true]
  );

  res.status(201).json({
    user: { id, name, email, role: 'member' },
    tempPassword,
    loginUrl: req.protocol + '://' + req.get('host') + '/login'
  });
});

// Admin: reset password
app.post('/api/admin/reset-password/:userId', authMiddleware, adminOnly, async (req, res) => {
  const result = await pool.query('SELECT id FROM users WHERE id=$1', [req.params.userId]);
  if (!result.rows.length) return res.status(404).json({ error: 'User not found' });

  const tempPassword = 'TF-' + Math.random().toString(36).substr(2, 6).toUpperCase();
  const hashed = await bcrypt.hash(tempPassword, 10);

  await pool.query(
    'UPDATE users SET password=$1, must_change_password=true WHERE id=$2',
    [hashed, req.params.userId]
  );
  res.json({ tempPassword, message: 'Password reset. User must change it on next login.' });
});

// Admin: generate magic link
app.post('/api/admin/generate-link/:userId', authMiddleware, adminOnly, async (req, res) => {
  const result = await pool.query('SELECT id FROM users WHERE id=$1', [req.params.userId]);
  if (!result.rows.length) return res.status(404).json({ error: 'User not found' });

  const linkToken = generateId() + generateId();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  await pool.query('DELETE FROM reset_links WHERE user_id=$1', [req.params.userId]);
  await pool.query(
    'INSERT INTO reset_links (token, user_id, expires_at) VALUES ($1,$2,$3)',
    [linkToken, req.params.userId, expiresAt]
  );

  const link = req.protocol + '://' + req.get('host') + '/access?token=' + linkToken;
  res.json({ link, expiresAt });
});

// Use magic link
app.get('/api/access-link/:token', async (req, res) => {
  const result = await pool.query('SELECT * FROM reset_links WHERE token=$1', [req.params.token]);
  const record = result.rows[0];
  if (!record) return res.status(400).json({ error: 'Invalid or expired link' });

  if (new Date() > new Date(record.expires_at)) {
    await pool.query('DELETE FROM reset_links WHERE token=$1', [req.params.token]);
    return res.status(400).json({ error: 'Link has expired' });
  }

  const userResult = await pool.query('SELECT * FROM users WHERE id=$1', [record.user_id]);
  const user = userResult.rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });

  await pool.query('DELETE FROM reset_links WHERE token=$1', [req.params.token]);
  await pool.query('UPDATE users SET must_change_password=true WHERE id=$1', [user.id]);

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET, { expiresIn: '7d' }
  );
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role }, mustChangePassword: true });
});

// Change password
app.post('/api/change-password', authMiddleware, async (req, res) => {
  const { newPassword, currentPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

  const result = await pool.query('SELECT * FROM users WHERE id=$1', [req.user.id]);
  const user = result.rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (!user.must_change_password) {
    if (!currentPassword) return res.status(400).json({ error: 'Current password required' });
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(400).json({ error: 'Current password is wrong' });
  }

  const hashed = await bcrypt.hash(newPassword, 10);
  await pool.query('UPDATE users SET password=$1, must_change_password=false WHERE id=$2', [hashed, user.id]);
  res.json({ message: 'Password changed successfully' });
});

// ---- PROJECTS ----
app.get('/api/projects', authMiddleware, async (req, res) => {
  let projects;
  if (req.user.role === 'admin') {
    const result = await pool.query('SELECT * FROM projects ORDER BY created_at DESC');
    projects = result.rows;
  } else {
    const result = await pool.query(
      'SELECT p.* FROM projects p JOIN project_members pm ON p.id=pm.project_id WHERE pm.user_id=$1 ORDER BY p.created_at DESC',
      [req.user.id]
    );
    projects = result.rows;
  }

  const enriched = await Promise.all(projects.map(async p => {
    const tasks = await pool.query('SELECT status FROM tasks WHERE project_id=$1', [p.id]);
    const members = await pool.query('SELECT id FROM project_members WHERE project_id=$1', [p.id]);
    const completed = tasks.rows.filter(t => t.status === 'done').length;
    return { ...p, taskCount: tasks.rows.length, memberCount: members.rows.length, completedTasks: completed };
  }));

  res.json(enriched);
});

app.post('/api/projects', authMiddleware, adminOnly, [
  body('name').trim().notEmpty().withMessage('Project name required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, description } = req.body;
  const id = generateId();

  await pool.query(
    'INSERT INTO projects (id, name, description, created_by) VALUES ($1,$2,$3,$4)',
    [id, name, description || '', req.user.id]
  );

  const memberId = generateId();
  await pool.query(
    'INSERT INTO project_members (id, project_id, user_id, role) VALUES ($1,$2,$3,$4)',
    [memberId, id, req.user.id, 'admin']
  );

  const result = await pool.query('SELECT * FROM projects WHERE id=$1', [id]);
  res.status(201).json(result.rows[0]);
});

app.get('/api/projects/:id', authMiddleware, async (req, res) => {
  const result = await pool.query('SELECT * FROM projects WHERE id=$1', [req.params.id]);
  const project = result.rows[0];
  if (!project) return res.status(404).json({ error: 'Project not found' });

  if (req.user.role !== 'admin') {
    const member = await pool.query(
      'SELECT id FROM project_members WHERE project_id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!member.rows.length) return res.status(403).json({ error: 'Access denied' });
  }

  const members = await pool.query(
    'SELECT u.id, u.name, u.email, pm.role FROM users u JOIN project_members pm ON u.id=pm.user_id WHERE pm.project_id=$1',
    [req.params.id]
  );

  res.json({ ...project, members: members.rows });
});

app.delete('/api/projects/:id', authMiddleware, adminOnly, async (req, res) => {
  const result = await pool.query('SELECT id FROM projects WHERE id=$1', [req.params.id]);
  if (!result.rows.length) return res.status(404).json({ error: 'Project not found' });

  await pool.query('DELETE FROM projects WHERE id=$1', [req.params.id]);
  res.json({ message: 'Project deleted' });
});

// ---- PROJECT MEMBERS ----
app.post('/api/projects/:id/members', authMiddleware, adminOnly, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  const project = await pool.query('SELECT id FROM projects WHERE id=$1', [req.params.id]);
  if (!project.rows.length) return res.status(404).json({ error: 'Project not found' });

  const user = await pool.query('SELECT id FROM users WHERE id=$1', [userId]);
  if (!user.rows.length) return res.status(404).json({ error: 'User not found' });

  try {
    await pool.query(
      'INSERT INTO project_members (id, project_id, user_id, role) VALUES ($1,$2,$3,$4)',
      [generateId(), req.params.id, userId, 'member']
    );
    res.json({ message: 'Member added' });
  } catch {
    res.status(400).json({ error: 'User already in project' });
  }
});

app.delete('/api/projects/:id/members/:userId', authMiddleware, adminOnly, async (req, res) => {
  await pool.query('DELETE FROM project_members WHERE project_id=$1 AND user_id=$2', [req.params.id, req.params.userId]);
  res.json({ message: 'Member removed' });
});

// ---- TASKS ----
app.get('/api/projects/:id/tasks', authMiddleware, async (req, res) => {
  if (req.user.role !== 'admin') {
    const member = await pool.query(
      'SELECT id FROM project_members WHERE project_id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!member.rows.length) return res.status(403).json({ error: 'Access denied' });
  }

  const result = await pool.query(
    `SELECT t.*, u.name as assignee_name 
     FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id 
     WHERE t.project_id=$1 ORDER BY t.created_at DESC`,
    [req.params.id]
  );
  res.json(result.rows);
});

app.post('/api/projects/:id/tasks', authMiddleware, [
  body('title').trim().notEmpty().withMessage('Task title required'),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  if (req.user.role !== 'admin') {
    const member = await pool.query(
      'SELECT id FROM project_members WHERE project_id=$1 AND user_id=$2',
      [req.params.id, req.user.id]
    );
    if (!member.rows.length) return res.status(403).json({ error: 'Access denied' });
  }

  const { title, description, assignedTo, priority, dueDate } = req.body;
  const id = generateId();

  await pool.query(
    `INSERT INTO tasks (id, project_id, title, description, assigned_to, priority, status, due_date, created_by)
     VALUES ($1,$2,$3,$4,$5,$6,'todo',$7,$8)`,
    [id, req.params.id, title, description || '', assignedTo || null, priority || 'medium', dueDate || null, req.user.id]
  );

  const result = await pool.query(
    'SELECT t.*, u.name as assignee_name FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id WHERE t.id=$1',
    [id]
  );
  res.status(201).json(result.rows[0]);
});

app.put('/api/tasks/:id', authMiddleware, async (req, res) => {
  const taskResult = await pool.query('SELECT * FROM tasks WHERE id=$1', [req.params.id]);
  const task = taskResult.rows[0];
  if (!task) return res.status(404).json({ error: 'Task not found' });

  if (req.user.role !== 'admin') {
    const member = await pool.query(
      'SELECT id FROM project_members WHERE project_id=$1 AND user_id=$2',
      [task.project_id, req.user.id]
    );
    if (!member.rows.length) return res.status(403).json({ error: 'Access denied' });
  }

  const { title, description, assignedTo, priority, status, dueDate } = req.body;
  await pool.query(
    `UPDATE tasks SET 
      title=COALESCE($1, title),
      description=COALESCE($2, description),
      assigned_to=$3,
      priority=COALESCE($4, priority),
      status=COALESCE($5, status),
      due_date=$6,
      updated_at=NOW()
    WHERE id=$7`,
    [title, description, assignedTo !== undefined ? assignedTo || null : task.assigned_to,
     priority, status, dueDate !== undefined ? dueDate || null : task.due_date, req.params.id]
  );

  const result = await pool.query(
    'SELECT t.*, u.name as assignee_name FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id WHERE t.id=$1',
    [req.params.id]
  );
  res.json(result.rows[0]);
});

app.delete('/api/tasks/:id', authMiddleware, async (req, res) => {
  const taskResult = await pool.query('SELECT * FROM tasks WHERE id=$1', [req.params.id]);
  const task = taskResult.rows[0];
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const isAdmin = req.user.role === 'admin';
  const isCreator = task.created_by === req.user.id;
  if (!isAdmin && !isCreator) return res.status(403).json({ error: 'Only admin or task creator can delete' });

  await pool.query('DELETE FROM tasks WHERE id=$1', [req.params.id]);
  res.json({ message: 'Task deleted' });
});

// ---- DASHBOARD ----
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  const now = new Date();
  let tasks, projects;

  if (req.user.role === 'admin') {
    const [t, p] = await Promise.all([
      pool.query('SELECT t.*, u.name as assignee_name, p.name as project_name FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id LEFT JOIN projects p ON t.project_id=p.id ORDER BY t.created_at DESC'),
      pool.query('SELECT * FROM projects')
    ]);
    tasks = t.rows; projects = p.rows;
  } else {
    const [t, p] = await Promise.all([
      pool.query(
        'SELECT t.*, u.name as assignee_name, p.name as project_name FROM tasks t LEFT JOIN users u ON t.assigned_to=u.id LEFT JOIN projects p ON t.project_id=p.id JOIN project_members pm ON t.project_id=pm.project_id WHERE pm.user_id=$1 ORDER BY t.created_at DESC',
        [req.user.id]
      ),
      pool.query(
        'SELECT p.* FROM projects p JOIN project_members pm ON p.id=pm.project_id WHERE pm.user_id=$1',
        [req.user.id]
      )
    ]);
    tasks = t.rows; projects = p.rows;
  }

  const myTasks = tasks.filter(t => t.assigned_to === req.user.id);
  const overdue = tasks.filter(t => t.due_date && new Date(t.due_date) < now && t.status !== 'done');

  res.json({
    totalProjects: projects.length,
    totalTasks: tasks.length,
    myTasks: myTasks.length,
    overdueTasks: overdue.length,
    statusBreakdown: {
      todo: tasks.filter(t => t.status === 'todo').length,
      inprogress: tasks.filter(t => t.status === 'inprogress').length,
      done: tasks.filter(t => t.status === 'done').length
    },
    recentTasks: tasks.slice(0, 5).map(t => ({
      ...t,
      assigneeName: t.assignee_name,
      projectName: t.project_name
    }))
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TaskFlow running on http://0.0.0.0:${PORT}`);
  });
}).catch(err => {
  console.error('DB init failed:', err);
  process.exit(1);
});