module.exports = (req, res, next) => {
	if (!req.user) {
		return res.status(401).json({
			error: true,
			reason: 'Unauthenticated',
		});
	}

	if (!req.user.role || req.user.role !== 'ADMIN') {
		return res.status(403).json({
			error: true,
			reason: `Access restricted to ADMIN users`,
		});
	}

	next();
};
