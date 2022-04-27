const router = require("express").Router();
const jwt = require('jsonwebtoken');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { BCRYPT_ROUNDS, JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const Users = require('../users/users-model')


router.post("/register", validateRoleName, (req, res, next) => {
  const hash = bcrypt.hashSync(req.body.password, BCRYPT_ROUNDS);

  let user = { username: req.body.username, password: hash, role_name: req.role_name }
  

  Users.add(user)
    .then(newUser => {
      res.status(201).json(newUser);
    })
    .catch(err => {
      next(err)
    })
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  function generateToken(user){
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name
    };
    const options = { expiresIn: '1d' };
    return jwt.sign(payload, JWT_SECRET, options);
  }

  Users.findBy({ username })
    .then(([user]) => {
      if(user && bcrypt.compareSync(password, user.password)){
        res.status(200).json({
          message: `${username} is back!`,
          token: generateToken(user)
        })
      }
    })
    .catch(next)

  
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
