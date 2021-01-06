const router = require('express').Router();
const passport = require('passport');
const IsEmail = require('isemail');
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

	if (!IsEmail.validate(email)) {
		return res.status(400).json({
			error: true,
			reason: `Invalid email address: ${email}`,
		});
	}

	try {
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
	} catch (err) {
		// If email already being used
		if (err.code && err.code === 'P2002') {
			return res.status(409).json({
				error: true,
				reason: `Email ${email} is not available`,
			});
		}

		return res.status(500).json({
			error: true,
			reason: 'Internal server error',
		});
	}
});

router.post('/login', passport.authenticate('local'));

module.exports = router;
