const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require("dotenv");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT;
const ENV = process.env.NODE_ENV;
// Connexion à la base de données
const db = mysql.createConnection({
  
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) throw err;
  console.log('Connected to the database');
});

const allowedEmail = process.env.ALLOWED_EMAIL;
const jwToken = process.env.JWT_SECRET;

// Endpoint pour l'enregistrement
app.post('/api/register', async (req, res) => {
  const { firstname, lastname, email, phone, password } = req.body;
  // Vérifier si l'email existe déjà
  const checkQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(checkQuery, [email], async (err, results) => {
    if (err) {
      res.status(500).send({ error: 'Server error' });
    } else if (results.length > 0) {
      res.status(400).send({ error: 'This email is already in use' });
    } else {
      // Hacher le mot de passe
      try {
        const hashedPassword = await bcrypt.hash(password, 10); // 10 = coût de hachage
        const insertQuery = 'INSERT INTO users (firstname, lastname, email, phone, password) VALUES (?, ?, ?, ?, ?)';
        db.query(insertQuery, [firstname, lastname, email, phone, hashedPassword], (err) => {
          if (err) {
            res.status(500).send({ error: 'Server error' });
          } else {
            res.send({ message: 'User registered successfully' });
          }
        });
      } catch (hashError) {
        res.status(500).send({ error: 'Error during password hash' });
      }
    }
  });
});

// Endpoint pour le login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const query = 'SELECT * FROM users WHERE email = ?';
  db.query(query, [email], async (err, results) => {
    if (err) {
      res.status(500).send({ error: 'Server error' });
    } else if (results.length===0) {
      res.status(401).send({ error: 'User not found' });
    } else if (results[0].email !== allowedEmail) {
      res.status(403).send({ error: 'Email not allowed' });
    } else {
      const user = results[0];
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        res.status(401).send({ error: 'Wrong password' });
      } else {
        res.send({ message: 'Successful connection' });
      }
    }
  });
});

// Middleware pour vérifier le token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).send({ error: 'Missing token' });

  jwt.verify(token, jwToken, (err, user) => {
    if (err) return res.status(403).send({ error: 'Invalide token' });
    req.user = user; // Stocker les informations utilisateur décodées
    next();
  });
};

// Exemple de route protégée
app.get('/api/protected', authenticateToken, (req, res) => {
  res.send({ message: `Welcome, user ID ${req.user.id}` });
});

// Enpoint to show all users
app.get("/api/users-with-orders", (req, res) => {
  const query = `SELECT u.id AS user_id, u.firstname, u.lastname, u.email, u.phone, 
  o.id AS order_id, o.service, o.length, o.treatment, o.date, o.hour FROM users u LEFT 
  JOIN appointments o ON u.id = o.user_id WHERE is_active = TRUE`;
  db.query(query, (err, results) => {
      if (err) { return res.status(500).send(err.message);
      return;
  }
  const users = {};
results.forEach((row) => {
  if (!users[row.user_id]) {
    users[row.user_id] = {
      id: row.id,
      firstname: row.firstname,
      lastname: row.lastname,
      email: row.email,
      phone: row.phone,
      appointments: []
    };
  }
  if (row.order_id){
    users[row.user_id].appointments.push({
      id: row.order_id,
      service: row.service,
      length: row.length,
      treatment: row.treatment,
      date: row.date,
      hour: row.hour
    });
  }
})  
  res.json(Object.values(users));
});
})

// Update User
app.put("/api/users/:id", (req, res) => {
  const { id } = req.params;
  const { firstname, lastname, email, phone } = req.body;
  const query = "UPDATE users SET firstname = ?, lastname = ?, email = ?, phone = ? WHERE id = ?";
  db.query(query, [firstname, lastname, email, phone, id], (err) => {
      if (err) return res.status(500).json(err);
      res.sendStatus(204);
  });
});

// Delete User
app.delete("/api/users/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM users WHERE id = ?";
  db.query(query, [id], (err) => {
      if (err) return res.status(500).json(err);
      res.sendStatus(204);
  });
});

// Endpoint to add an appointment
app.post('/api/appointments', (req, res) => {
  const { user_id, service, length, treatment, date, hour } = req.body;
  const sql = "INSERT INTO appointments (user_id, service, length, treatment, date, hour) VALUES (?, ?, ?, ?, ?, ?)";
  db.query(sql, [user_id, service, length, treatment, date, hour], (err, result) => {
      if (err) {
          console.error(err);
          res.status(500).send({error: 'Error saving appointment'});
      } else {
          res.status(200).send({message: 'Appointment saved successfully!'});
      }
  });
});

// Route pour vérifier si l'email existe
app.get("/api/users/check-email", (req, res) => {
  const { email } = req.query;
  const sql = "SELECT id, firstname FROM users WHERE email = ?";
  db.query(sql, [email], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.length > 0) {
      res.status(200).json({ exists: true,
        id: result[0].id,
        firstname: result[0].firstname });
    } else {
      res.status(200).json({ exists: false });
    }
  });
});

// Démarrer le serveur
app.listen(process.env.PORT, () => {
  const baseURL = ENV === 'production' 
  ? 'https://github.com/jesledev/mayab_api.git' : `http://localhost:${PORT}`;
  console.log(`Server is running on ${baseURL}`);
});
