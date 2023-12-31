const express = require('express')
const {
 
  verifyToken
} = require('../controllers/userController')

const router = express.Router()


// Get a new Toeken valididty
router.get('/', verifyToken)


module.exports = router