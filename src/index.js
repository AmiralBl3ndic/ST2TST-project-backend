require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const cors = require('cors');
const LocalStrategy = require('./auth/local.strategy');
const apiRoutes = require('./routes/api.routes');
const UserService = require('./services/user.service');

const app = express();

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
	const user = await UserService.findById(id);

	if (!user) return done(null, false);
	return done(null, user);
});

app.use(cors());
app.use(
	session({
		secret: process.env.SESSION_SECRET || 'OZIURFGQETGOPUIuyvutv',
		resave: false,
		saveUninitialized: true,
	})
);
app.use(passport.initialize());
app.use(passport.session());

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

passport.use('local', LocalStrategy);

app.use('/', apiRoutes);

app.use((req, res, next) => {
	return res.status(404).json({
		error: true,
		reason: 'Resource not found',
	});
});

const port = 8080 || process.env.PORT;
app.listen(port, () => {
	console.log(`Server started and listening on port ${port}`);
});
