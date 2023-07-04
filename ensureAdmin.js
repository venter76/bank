// ensureAdmin.js

function ensureAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
      return next();
    }
  
    // Redirect or show an error message if the user is not an admin
    res.status(403).send('Access denied');
  }
  
  module.exports = ensureAdmin;
  