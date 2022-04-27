const Users = require('../users/users-model');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!


const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  
  if(!token){
    next({ status: 401, message: 'Token required' });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
    if(err){
      next({ status: 401, message: "Token invalid" });
      return;
    }

    req.decodedJwt = decodedToken;
    next();
  })
}

const only = role_name => (req, res, next) => {
    if(req.decodedJwt.role_name !== role_name){
      next({ status: 403, message: 'This is not for you' });
      return;
    } else {
      next();
    }
}


const checkUsernameExists = (req, res, next) => {
  const { username } = req.body;
  
  Users.findBy({ username })
    .then(user => {
      if(!user[0]){
        next({ status: 401, message: "Invalid credentials" });
        return;
      } else {
        next();
      }

    })
}


const validateRoleName = (req, res, next) => {
  const roleName = req.body.role_name;

  if(!roleName || roleName.trim() === ''){
    req.role_name = 'student';
    next();
  } else if(roleName.trim() === 'admin') {
    next({ status: 422, message: "Role name can not be admin" })
    return;
  } else if(roleName.trim().length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" })
    return;
  } else {
    req.role_name = roleName.trim();
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
