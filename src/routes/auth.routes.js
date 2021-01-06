const router = require('express').Router();
const passport = require('passport');
const UserService = require('../services/user.service');

router.post('/register', async (req, res) => {
	const { email, password } = req.body;

	if ([email, password].some((_) => _ == null)) {
		return res.status(400).json({
			error: true,
			reason: 'Both "email" and "password" fields must be defined',
		});
	}

	if ([email, password].some((_) => _.length < 3)) {
		return res.status(400).json({
			error: true,
			reason: 'Both "email" and "password" must be at least 3 characters',
		});
	}

	const createdUser = await UserService.createUser(email, password);

	if (!createdUser) {
		return res.status(500).json({
			error: true,
			reason: 'Unable to create user',
		});
	}

	return res.status(201).json({
		error: false,
		user: createdUser,
	});
});

router.post('/login', passport.authenticate('local'));

module.exports = router;
