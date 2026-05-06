const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const { body, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'taskflow_secret_key_2024';

// Setup DB
const adapter = new FileSync('db.json');
const db = low(adapter);

db.defaults({
  users: [],
  projects: [],
  tasks: [],
  projectMembers: [],
  resetLinks: []
}).write();

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
  const exists = db.get('users').find({ email }).value();
  if (exists) return res.status(400).json({ error: 'Email already in use' });

  const hashed = await bcrypt.hash(password, 10);
  const user = {
    id: generateId(),
    name,
    email,
    password: hashed,
    role: role === 'admin' ? 'admin' : 'member',
    createdAt: new Date().toISOString()
  };

  db.get('users').push(user).write();
  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

  const user = db.get('users').find({ email }).value();
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
    mustChangePassword: !!user.mustChangePassword
  });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.get('users').find({ id: req.user.id }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ id: user.id, name: user.name, email: user.email, role: user.role });
});

// ---- USERS (admin only) ----
app.get('/api/users', authMiddleware, (req, res) => {
  const users = db.get('users').map(u => ({
    id: u.id, name: u.name, email: u.email, role: u.role,
    mustChangePassword: !!u.mustChangePassword,
    createdAt: u.createdAt
  })).value();
  res.json(users);
});

// Admin: create a member with temp password
app.post('/api/admin/create-member', authMiddleware, adminOnly, async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email) return res.status(400).json({ error: 'Name and email required' });

  const exists = db.get('users').find({ email }).value();
  if (exists) return res.status(400).json({ error: 'Email already in use' });

  // Generate a readable temp password
  const tempPassword = 'TF-' + Math.random().toString(36).substr(2, 6).toUpperCase();
  const hashed = await bcrypt.hash(tempPassword, 10);

  const user = {
    id: generateId(),
    name,
    email,
    password: hashed,
    role: 'member',
    mustChangePassword: true,
    createdAt: new Date().toISOString()
  };

  db.get('users').push(user).write();
  // Return plain temp password to admin (only time it's visible)
  res.status(201).json({
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
    tempPassword,
    loginUrl: req.protocol + '://' + req.get('host') + '/login'
  });
});

// Admin: reset any user's password
app.post('/api/admin/reset-password/:userId', authMiddleware, adminOnly, async (req, res) => {
  const user = db.get('users').find({ id: req.params.userId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });

  const tempPassword = 'TF-' + Math.random().toString(36).substr(2, 6).toUpperCase();
  const hashed = await bcrypt.hash(tempPassword, 10);

  db.get('users').find({ id: req.params.userId }).assign({
    password: hashed,
    mustChangePassword: true
  }).write();

  res.json({ tempPassword, message: 'Password reset. User must change it on next login.' });
});

// Admin: generate a magic access link (token valid 24h)
app.post('/api/admin/generate-link/:userId', authMiddleware, adminOnly, (req, res) => {
  const user = db.get('users').find({ id: req.params.userId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });

  const linkToken = generateId() + generateId();
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  // Remove old links for this user
  db.get('resetLinks').remove({ userId: user.id }).write();
  db.get('resetLinks').push({ token: linkToken, userId: user.id, expiresAt }).write();

  const link = req.protocol + '://' + req.get('host') + '/access?token=' + linkToken;
  res.json({ link, expiresAt });
});

// Use magic link to login
app.get('/api/access-link/:token', (req, res) => {
  const record = db.get('resetLinks').find({ token: req.params.token }).value();
  if (!record) return res.status(400).json({ error: 'Invalid or expired link' });
  if (new Date() > new Date(record.expiresAt)) {
    db.get('resetLinks').remove({ token: req.params.token }).write();
    return res.status(400).json({ error: 'Link has expired' });
  }

  const user = db.get('users').find({ id: record.userId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Consume link
  db.get('resetLinks').remove({ token: req.params.token }).write();
  // Mark must change password
  db.get('users').find({ id: user.id }).assign({ mustChangePassword: true }).write();

  const token = jwt.sign({ id: user.id, email: user.email, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
  res.json({
    token,
    user: { id: user.id, name: user.name, email: user.email, role: user.role },
    mustChangePassword: true
  });
});

// Change password (logged-in user, forced or voluntary)
app.post('/api/change-password', authMiddleware, async (req, res) => {
  const { newPassword, currentPassword } = req.body;
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });

  const user = db.get('users').find({ id: req.user.id }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });

  // If not mustChangePassword, require current password
  if (!user.mustChangePassword) {
    if (!currentPassword) return res.status(400).json({ error: 'Current password required' });
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(400).json({ error: 'Current password is wrong' });
  }

  const hashed = await bcrypt.hash(newPassword, 10);
  db.get('users').find({ id: req.user.id }).assign({ password: hashed, mustChangePassword: false }).write();
  res.json({ message: 'Password changed successfully' });
});

// ---- PROJECTS ----
app.get('/api/projects', authMiddleware, (req, res) => {
  let projects;
  if (req.user.role === 'admin') {
    projects = db.get('projects').value();
  } else {
    const memberOf = db.get('projectMembers').filter({ userId: req.user.id }).map('projectId').value();
    projects = db.get('projects').filter(p => memberOf.includes(p.id)).value();
  }

  // Enrich with task stats
  projects = projects.map(p => {
    const tasks = db.get('tasks').filter({ projectId: p.id }).value();
    const members = db.get('projectMembers').filter({ projectId: p.id }).value().length;
    return { ...p, taskCount: tasks.length, memberCount: members, completedTasks: tasks.filter(t => t.status === 'done').length };
  });

  res.json(projects);
});

app.post('/api/projects', authMiddleware, adminOnly, [
  body('name').trim().notEmpty().withMessage('Project name required'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, description } = req.body;
  const project = {
    id: generateId(),
    name,
    description: description || '',
    createdBy: req.user.id,
    createdAt: new Date().toISOString()
  };
  db.get('projects').push(project).write();

  // Auto-add creator as member
  db.get('projectMembers').push({ id: generateId(), projectId: project.id, userId: req.user.id, role: 'admin' }).write();
  res.status(201).json(project);
});

app.get('/api/projects/:id', authMiddleware, (req, res) => {
  const project = db.get('projects').find({ id: req.params.id }).value();
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const isMember = req.user.role === 'admin' || db.get('projectMembers').find({ projectId: project.id, userId: req.user.id }).value();
  if (!isMember) return res.status(403).json({ error: 'Access denied' });

  const members = db.get('projectMembers').filter({ projectId: project.id }).value().map(pm => {
    const u = db.get('users').find({ id: pm.userId }).value();
    return u ? { id: u.id, name: u.name, email: u.email, role: pm.role } : null;
  }).filter(Boolean);

  res.json({ ...project, members });
});

app.delete('/api/projects/:id', authMiddleware, adminOnly, (req, res) => {
  const project = db.get('projects').find({ id: req.params.id }).value();
  if (!project) return res.status(404).json({ error: 'Project not found' });

  db.get('projects').remove({ id: req.params.id }).write();
  db.get('tasks').remove({ projectId: req.params.id }).write();
  db.get('projectMembers').remove({ projectId: req.params.id }).write();
  res.json({ message: 'Project deleted' });
});

// ---- PROJECT MEMBERS ----
app.post('/api/projects/:id/members', authMiddleware, adminOnly, (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  const project = db.get('projects').find({ id: req.params.id }).value();
  if (!project) return res.status(404).json({ error: 'Project not found' });

  const user = db.get('users').find({ id: userId }).value();
  if (!user) return res.status(404).json({ error: 'User not found' });

  const already = db.get('projectMembers').find({ projectId: req.params.id, userId }).value();
  if (already) return res.status(400).json({ error: 'User already in project' });

  db.get('projectMembers').push({ id: generateId(), projectId: req.params.id, userId, role: 'member' }).write();
  res.json({ message: 'Member added' });
});

app.delete('/api/projects/:id/members/:userId', authMiddleware, adminOnly, (req, res) => {
  db.get('projectMembers').remove({ projectId: req.params.id, userId: req.params.userId }).write();
  res.json({ message: 'Member removed' });
});

// ---- TASKS ----
app.get('/api/projects/:id/tasks', authMiddleware, (req, res) => {
  const isMember = req.user.role === 'admin' || db.get('projectMembers').find({ projectId: req.params.id, userId: req.user.id }).value();
  if (!isMember) return res.status(403).json({ error: 'Access denied' });

  let tasks = db.get('tasks').filter({ projectId: req.params.id }).value();

  // Enrich with assignee name
  tasks = tasks.map(t => {
    const assignee = t.assignedTo ? db.get('users').find({ id: t.assignedTo }).value() : null;
    return { ...t, assigneeName: assignee ? assignee.name : null };
  });

  res.json(tasks);
});

app.post('/api/projects/:id/tasks', authMiddleware, [
  body('title').trim().notEmpty().withMessage('Task title required'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const isMember = req.user.role === 'admin' || db.get('projectMembers').find({ projectId: req.params.id, userId: req.user.id }).value();
  if (!isMember) return res.status(403).json({ error: 'Access denied' });

  const { title, description, assignedTo, priority, dueDate } = req.body;
  const task = {
    id: generateId(),
    projectId: req.params.id,
    title,
    description: description || '',
    assignedTo: assignedTo || null,
    priority: priority || 'medium',
    status: 'todo',
    dueDate: dueDate || null,
    createdBy: req.user.id,
    createdAt: new Date().toISOString()
  };
  db.get('tasks').push(task).write();

  const assignee = task.assignedTo ? db.get('users').find({ id: task.assignedTo }).value() : null;
  res.status(201).json({ ...task, assigneeName: assignee ? assignee.name : null });
});

app.put('/api/tasks/:id', authMiddleware, (req, res) => {
  const task = db.get('tasks').find({ id: req.params.id }).value();
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const isMember = req.user.role === 'admin' || db.get('projectMembers').find({ projectId: task.projectId, userId: req.user.id }).value();
  if (!isMember) return res.status(403).json({ error: 'Access denied' });

  const allowed = ['title', 'description', 'assignedTo', 'priority', 'status', 'dueDate'];
  const updates = {};
  allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
  updates.updatedAt = new Date().toISOString();

  db.get('tasks').find({ id: req.params.id }).assign(updates).write();
  const updated = db.get('tasks').find({ id: req.params.id }).value();
  const assignee = updated.assignedTo ? db.get('users').find({ id: updated.assignedTo }).value() : null;
  res.json({ ...updated, assigneeName: assignee ? assignee.name : null });
});

app.delete('/api/tasks/:id', authMiddleware, (req, res) => {
  const task = db.get('tasks').find({ id: req.params.id }).value();
  if (!task) return res.status(404).json({ error: 'Task not found' });

  const isAdmin = req.user.role === 'admin';
  const isCreator = task.createdBy === req.user.id;
  if (!isAdmin && !isCreator) return res.status(403).json({ error: 'Only admin or task creator can delete' });

  db.get('tasks').remove({ id: req.params.id }).write();
  res.json({ message: 'Task deleted' });
});

// ---- DASHBOARD ----
app.get('/api/dashboard', authMiddleware, (req, res) => {
  const now = new Date();
  let tasks, projects;

  if (req.user.role === 'admin') {
    tasks = db.get('tasks').value();
    projects = db.get('projects').value();
  } else {
    const memberOf = db.get('projectMembers').filter({ userId: req.user.id }).map('projectId').value();
    projects = db.get('projects').filter(p => memberOf.includes(p.id)).value();
    tasks = db.get('tasks').filter(t => memberOf.includes(t.projectId)).value();
  }

  const myTasks = tasks.filter(t => t.assignedTo === req.user.id);
  const overdue = tasks.filter(t => t.dueDate && new Date(t.dueDate) < now && t.status !== 'done');

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
    recentTasks: tasks.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 5).map(t => {
      const assignee = t.assignedTo ? db.get('users').find({ id: t.assignedTo }).value() : null;
      const project = db.get('projects').find({ id: t.projectId }).value();
      return { ...t, assigneeName: assignee?.name, projectName: project?.name };
    })
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`TaskFlow running on http://localhost:${PORT}`);
});