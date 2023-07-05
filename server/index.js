const express = require('express');
const app = express();
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const path = require('path');

const Users = require('./models/Users');
const Tasks = require('./models/Tasks');

app.use(cookieParser());
app.use(express.static('public'));
app.use(cors({
  origin: true,
  credentials: true,
}));
dotenv.config();
app.use(express.json())

//Databse connection
mongoose.connect(process.env.DATABASE_CONNECTION_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

//JWT secret key
const jwtSecret = process.env.JWT_SECRET_KEY

//Uploading profile picture
const storage = multer.diskStorage({
  destination: function (req, file, callback) {
    callback(null, 'public/uploads/');
  },
  filename: function (req, file, callback) {
    callback(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

//Registering a new user
app.post('/register', upload.single('filename'), async (req, res) => {
  const { name, email, password } = req.body;
  const { filename } = req.file;
  const securePass = bcrypt.hashSync(password, 15);
  try {
    // Check if user already exists
    const existingUser = await Users.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User already exists' });
    }

    //Creating a new user if not already presnt
    const createdUser = await Users.create({ name, email, photo: filename, password: securePass });
    //Assigning a cookie
    jwt.sign({ userId: createdUser._id, name: createdUser.name, photo: createdUser.photo, email: createdUser.email }, jwtSecret, {}, (err, token) => {
      if (err) throw err;
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', path: '/' }).status(201).json({ name: createdUser.name, email: createdUser.email, photo: createdUser.photo });
    })
  } catch (err) {
    res.status(401).json({ error: "User cannot be created" });
  }
});

//Logging in an existing user
app.post('/login', upload.none(), async (req, res) => {
  const { email, password } = req.body;
  try {
    const findUser = await Users.findOne({ email: email });
    if (findUser) {
      const passOk = bcrypt.compareSync(password, findUser.password);
      if (passOk) {
        jwt.sign({ userId: findUser._id, name: findUser.name, email: findUser.email, photo: findUser.photo }, jwtSecret, {}, (err, token) => {
          if (err) throw err;
          res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', path: '/' }).status(200).json(findUser);
        });
      } else {
        res.status(401).json({ error: "Password not matched" });
      }
    } else {
      res.status(401).json({ error: 'User not found' });
    }
  }
  catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
})

//Fetching the profile of the logged in user
app.get('/profile', (req, res) => {
  const { token } = req.cookies;
  if (token) {
    jwt.verify(token, jwtSecret, {}, (err, data) => {
      if (err) throw err;
      res.json(data);
    });
  } else {
    res.status(401).json('No token');
  }
});


app.get('/users', async (req, res) => {
  try {
    const users = await Users.find();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

app.post('/addtask', async (req, res) => {
  const { title, description, duedate, status, assign, assignedUserId } = req.body;
  try {
    //Creating a new task if not already created
    const createdTask = await Tasks.create({ title, description, duedate, status, assignedtouser: assign, assigneduserid: assignedUserId });
    if (createdTask) {
      res.json(201).json({ message: "Task Created" })
    }
  } catch (err) {
    res.status(401).json({ error: "Task cannot be created" });
  }
})


// Fetch tasks for the logged-in user
app.get("/tasks", async (req, res) => {
  try {
    const { userId } = req.query;

    // Check if user already exists
    const existingUser = await Users.findById(userId);

    if (existingUser) {
      // Find tasks assigned to the user
      const tasks = await Tasks.find({ assigneduserid: userId });

      res.status(200).json(tasks);
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});




//User Logging out
app.post('/logout', (req, res) => {
  res.cookie('token', '').json("Logged Out");
})

app.listen(4001)