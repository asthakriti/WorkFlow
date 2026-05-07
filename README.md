# TaskFlow

A full-stack team task management app with role-based access, project organization, Kanban boards, and a dark-themed UI. Built with Node.js, Express, and PostgreSQL.

---

## Features

**Project & Task Management**
- Create projects, assign members, and track progress with visual progress bars
- Tasks support priorities (low / medium / high), due dates, assignees, and status tracking
- Switch between a Kanban board view and a traditional list view
- Filter tasks by status, priority, or assignee
- Click-to-cycle task statuses: todo → in progress → done

**Authentication & Admin**
- JWT-based auth with bcrypt password hashing
- Admin and member roles with route-level authorization
- Admins can create team members with auto-generated temporary passwords
- Password resets and time-limited magic access links for onboarding
- Forced password change flow for new or reset accounts

**Dashboard**
- Overview stats: total projects, tasks, personal assignments, overdue count
- Status breakdown and recent task activity

---

## Tech Stack

| Layer        | Technology                              |
|--------------|-----------------------------------------|
| Server       | Node.js + Express                       |
| Database     | PostgreSQL (via `pg`)                   |
| Auth         | jsonwebtoken + bcryptjs                 |
| Validation   | express-validator                       |
| Frontend     | Vanilla HTML, CSS, and JavaScript       |
| Fonts        | Sora, JetBrains Mono (Google Fonts)     |

---

## Getting Started

### Prerequisites

- Node.js v16+
- PostgreSQL (local or remote)

### Setup

```bash
git clone https://github.com/asthakriti/WorkFlow.git
cd WorkFlow
npm install
```

Create a `.env` file in the project root:

```env
DATABASE_URL=postgresql://user:password@localhost:5432/taskflow
JWT_SECRET=your_secret_key
PORT=3000
```

| Variable       | Description                              | Default                    |
|----------------|------------------------------------------|----------------------------|
| `DATABASE_URL` | PostgreSQL connection string             | *(required)*               |
| `JWT_SECRET`   | Secret for signing JWT tokens            | `taskflow_secret_key_2024` |
| `PORT`         | Server port                              | `3000`                     |
| `NODE_ENV`     | Set to `production` to enable DB SSL     | —                          |

### Run

```bash
npm start
```

Tables are created automatically on first startup. The app will be available at `http://localhost:3000`.

---

## Project Structure

```
WorkFlow/
├── server.js           # Express server, API routes, auth, DB init
├── public/
│   └── index.html      # Single-page frontend (HTML + CSS + JS)
├── package.json
├── .gitignore
└── README.md
```

---

## API Reference

Protected routes require an `Authorization: Bearer <token>` header.

### Auth

| Method | Endpoint               | Auth | Description                   |
|--------|------------------------|------|-------------------------------|
| POST   | `/api/signup`          | No   | Register a new user           |
| POST   | `/api/login`           | No   | Login, returns JWT            |
| GET    | `/api/me`              | Yes  | Get current user profile      |
| POST   | `/api/change-password` | Yes  | Change password               |

### Users (Admin)

| Method | Endpoint                            | Description                           |
|--------|-------------------------------------|---------------------------------------|
| GET    | `/api/users`                        | List all users                        |
| POST   | `/api/admin/create-member`          | Create member with temp password      |
| POST   | `/api/admin/reset-password/:userId` | Reset a user's password               |
| POST   | `/api/admin/generate-link/:userId`  | Generate a magic access link (24h)    |
| GET    | `/api/access-link/:token`           | Redeem a magic link (no auth needed)  |

### Projects

| Method | Endpoint                            | Auth  | Description                    |
|--------|-------------------------------------|-------|--------------------------------|
| GET    | `/api/projects`                     | Yes   | List projects (scoped by role) |
| POST   | `/api/projects`                     | Admin | Create a project               |
| GET    | `/api/projects/:id`                 | Yes   | Project details + members      |
| DELETE | `/api/projects/:id`                 | Admin | Delete a project               |
| POST   | `/api/projects/:id/members`         | Admin | Add member to project          |
| DELETE | `/api/projects/:id/members/:userId` | Admin | Remove member from project     |

### Tasks

| Method | Endpoint                    | Auth | Description                         |
|--------|-----------------------------|------|-------------------------------------|
| GET    | `/api/projects/:id/tasks`   | Yes  | List tasks for a project            |
| POST   | `/api/projects/:id/tasks`   | Yes  | Create a task                       |
| PUT    | `/api/tasks/:id`            | Yes  | Update a task                       |
| DELETE | `/api/tasks/:id`            | Yes  | Delete (admin or task creator only) |

### Dashboard

| Method | Endpoint          | Auth | Description                                  |
|--------|-------------------|------|----------------------------------------------|
| GET    | `/api/dashboard`  | Yes  | Stats, status breakdown, and recent tasks    |

---

## Database

Five tables, all auto-created on startup:

| Table             | Purpose                                |
|-------------------|----------------------------------------|
| `users`           | Accounts with hashed passwords         |
| `projects`        | Project metadata                       |
| `tasks`           | Tasks linked to projects and assignees |
| `project_members` | Project-user membership (many-to-many) |
| `reset_links`     | Magic link tokens with expiry          |

---

## Roles & Permissions

| Action                  | Admin | Member |
|-------------------------|:-----:|:------:|
| View dashboard          |  Yes  |  Yes   |
| View assigned projects  |  Yes  |  Yes   |
| View all projects       |  Yes  |  No    |
| Create / delete projects|  Yes  |  No    |
| Manage project members  |  Yes  |  No    |
| Create / edit tasks     |  Yes  |  Yes   |
| Delete any task         |  Yes  |  No    |
| Delete own task         |  Yes  |  Yes   |
| Manage team accounts    |  Yes  |  No    |

---

## License

MIT
