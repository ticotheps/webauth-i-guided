const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session'); // (Day 2) Step 1: Install + Import express-session

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

// (Day 2) Step 3: Define 'sessionConfig'
const sessionConfig = {
  name: 'monkey',
  secret: 'keep it secret, keep it safe!',
  cookie: {
    maxAge: 1000 * 60 * 15, // time that the cookie lives (in milliseconds); equal to '15 minutes'
    secure: false, // used over https ONLY; 'false' for development purposes, 'true' for production
  },
  httpOnly: true, // cannot access the cookie from JS using document.cookie; you want this 'true' 99% of the time
  resave: false, // "Do I want to save this every time, on every request, even if nothing has changed?"
  saveUninitialized: false, // GDPR laws against setting cookies automatically so keep it 'false'
}

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig)); // (Day 2) Step 2: Tells the server to use express-session

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;

  // generate hash from user's password
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n ("rounds" of hashing)
  // this is a synchronous process = it must wait until a username an password is 
  // provided before allowing a user to login

  // override user.password with hash
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username }) // same as 'where' and passing in 'id'
    .first()
    .then(user => {
      // check that passwords match
      if (user && bcrypt.compareSync(password, user.password)) {
        // HERE is where we would like to save cookie data regarding the session
        req.session.username = user.username;

        res.status(200).json({ message: `Welcome ${user.username}!, have a cookie...` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// (Day 2) Step 4: Modify the old middleware with simpler syntax that uses sessions
// new middleware with use of cookies
function restricted(req, res, next) {

  if (req.session && req.session.username) {
    next();
  } else {
    res.status(401).json({ message: 'You shall not pass!' });
  }
}

// BELOW CODE IS NO LONGER NEEDED BECAUSE OF COOKIES
// -------OLD MIDDLEWARE (BEFORE COOKIES)-----------
// function restricted(req, res, next) {
//   const { username, password } = req.headers;

//   if (username && password) {
//     Users.findBy({ username })
//     .first()
//     .then(user => {
//       // check that passwords match
//       if (user && bcrypt.compareSync(password, user.password)) {
//         next();
//       } else {
//         res.status(401).json({ message: 'Invalid Credentials' });
//       }
//     })
//     .catch(error => {
//       res.status(500).json({ message: 'Ran into an unexpected error' });
//     });
//   } else {
//     res.status(400).json({ message: 'No credentials provided' });
//   }
// }

// if using axios, the syntax will look like this: 
// "axios.get(url, { headers: { username, password } })"


// Goal: protect this route! Only authenticated users should see it!
// If using postman, a user should NOT be able to return the list 
// of users when performing a GET request and using the headers as
// the means of passing the 'username' and 'password' to the endpoint
// (instead of doing a POST request and passing those key/value pairs as
// an object on req.body).
server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// BELOW: Proper syntax to make the above GET request handler asynchronous with a
// different endpoint
//
// server.get('/users', restricted, async (req, res) => {
//   try {
//     const users = await Users.find();

//     res.json(users);
//   } catch (error) {
//     res.send(err)
//   }
// });

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
