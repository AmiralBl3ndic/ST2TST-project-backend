const router = require('express').Router();
const passport = require('passport');
const IsEmail = require('isemail');
const UserService = require('../services/user.service');
const isAuthenticated = require('../auth/is-authenticated.middleware');
const isAdmin = require('../auth/is-admin.middleware');

////////////////////////////////////////////////////////////
// Currently authenticated user
////////////////////////////////////////////////////////////

router.get('/me', isAuthenticated, (req, res) => {
	return res.status(200).json({
		error: false,
		user: req.user,
	});
});

////////////////////////////////////////////////////////////
// Change password
////////////////////////////////////////////////////////////

router.put('/me/password', isAuthenticated, async (req, res) => {
	const { oldPassword, newPassword } = req.body || {};

	if (!oldPassword || !newPassword) {
		return res.status(400).json({
			error: true,
			reason: 'oldPassword and newPassword fields must be set',
		});
	}

	if (newPassword.length < 3) {
		return res.status(400).json({
			error: true,
			reason: 'New password must be at least 3 characters long',
		});
	}

	try {
		await UserService.updatePassword(req.user.email, oldPassword, newPassword);
		return res.status(204).send();
	} catch (err) {
		console.error(err);
		return res.status(500).json({
			error: true,
			reason: 'Internal server error',
		});
	}
});

////////////////////////////////////////////////////////////
// Login / Register
////////////////////////////////////////////////////////////

router.post('/login', passport.authenticate('local'), (req, res) => {
	return res.status(200).json({
		error: false,
		message: 'Logged in',
		user: {
			email: req.user.email,
			role: req.user.role,
		},
	});
});

router.post('/register', async (req, res) => {
	const { email, password } = req.body;

	if ([email, password].some((_) => _ == null)) {
		return res.status(400).json({
			error: true,
			reason: 'Both email and password fields must be defined',
		});
	}

	if ([email, password].some((_) => _.length < 3)) {
		return res.status(400).json({
			error: true,
			reason: 'Both email and password must be at least 3 characters',
		});
	}

	if (!IsEmail.validate(email)) {
		return res.status(400).json({
			error: true,
			reason: `Invalid email address: ${email}`,
		});
	}

	try {
		const authorizedEmailsRecord = await UserService.getAuthorizedEmailRecord(
			email
		);

		if (!authorizedEmailsRecord) {
			return res.status(403).json({
				error: true,
				reason: 'Unauthorized email address',
			});
		}

		const createdUser = await UserService.createUser(
			email,
			password,
			authorizedEmailsRecord.role
		);

		if (!createdUser) {
			return res.status(500).json({
				error: true,
				reason: 'Unable to create user',
			});
		}

		return res.status(201).json({
			error: false,
			user: {
				email: createdUser.email,
				role: createdUser.role,
			},
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

router.get('/logout', (req, res) => {
	req.logout();
	return res.status(200).json({
		error: false,
		message: 'Logged out',
	});
});

////////////////////////////////////////////////////////////
// Authorized emails
////////////////////////////////////////////////////////////

router.get('/authorized-emails', isAdmin, async (req, res) => {
	try {
		return res.status(200).json(await UserService.getAuthorizedEmails());
	} catch (err) {
		console.error(err);
		return res.status(500).json({
			error: true,
			reason: 'Internal server error',
		});
	}
});

router.post('/authorized-emails', isAdmin, async (req, res) => {
	const { email, role } = req.body;

	if ([email, role].some((x) => !x)) {
		return res.status(400).json({
			error: true,
			reason: 'Both email and role fields must be set',
		});
	}

	if (!IsEmail.validate(email)) {
		return res.status(400).json({
			error: true,
			reason: `Email address ${email} is invalid`,
		});
	}

	if (!['ADMIN', 'EMPLOYEE'].some((r) => r === role)) {
		return res.status(400).json({
			error: true,
			reason: 'role field must be either ADMIN or EMPLOYEE',
		});
	}

	try {
		await UserService.addAuthorizedEmail(email, role);

		return res.status(201).json({
			error: false,
			authorized: {
				email,
				role,
			},
		});
	} catch (err) {
		if (err.code && err.code === 'P2002') {
			return res.status(409).json({
				error: true,
				reason: `Email ${email} is already authorized`,
			});
		}

		return res.status(500).json({
			error: true,
			reason: 'Internal server error',
		});
	}
});

router.put('/authorized-emails/:email', isAdmin, async (req, res) => {
	const { email } = req.params;
	const { role } = req.body;

	if (!IsEmail.validate(email)) {
		return res.status(400).json({
			error: true,
			reason: `Email address ${email} is invalid`,
		});
	}

	if (!['ADMIN', 'EMPLOYEE'].some((r) => r === role)) {
		return res.status(400).json({
			error: true,
			reason: 'role field must be either ADMIN or EMPLOYEE',
		});
	}

	try {
		await UserService.updateAuthorizedEmailRole(email, role);
		return res.status(204).send();
	} catch (err) {
		return res.status(500).json({
			error: true,
			reason: 'Internal server error',
		});
	}
});

router.delete('/authorized-emails/:email', isAdmin, async (req, res) => {
	const { email } = req.params;

	if (!IsEmail.validate(email)) {
		return res.status(400).json({
			error: true,
			reason: `Email address ${email} is invalid`,
		});
	}

	try {
		await UserService.deleteAuthorizedEmail(email);
		return res.status(204).send();
	} catch (err) {
		return res.status(500).json({
			error: true,
			reason: 'Internal server error',
		});
	}
});

module.exports = router;
