const express = require('express')
const {
  createUser,
  updateUser,
  deleteUser,
  getUserMessages,
  addMessageToUser,
  search
} = require('../controllers/userController')

const router = express.Router()


// POST a new User
router.post('/', createUser)

//Add Messge for user
router.post('/:username',addMessageToUser)


// GET a single User
router.get('/:id', getUserMessages)

//ALL USERNAMES
router.get('/search/:username/:page', search)


// DELETE a User
router.delete('/:id', deleteUser)

// UPDATE a User
router.patch('/:id', updateUser)


module.exports = router