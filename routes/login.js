const express = require('express')
const {
  loginUser,
  
} = require('../controllers/userController')

const router = express.Router()

// POST a new User
router.post('/', loginUser)




module.exports = router