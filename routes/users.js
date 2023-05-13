const express = require('express');
const passport = require('passport');
const authenticate = require('../authenticate');

const User = require('../models/users');

const router = express.Router();

/* GET users listing. */
router.get('/', function (req, res, next) {
	res.send('respond with a resource');
});

router.post('/signup', (req, res) => {
	User.register(
		new User({ username: req.body.username }), // This is the username
		req.body.password, // This is the password
		(err) => {
			if (err) {
				res.statusCode = 500;
				res.setHeader('Content-Type', 'application/json');
				res.json({ err: err });
			} else {
				passport.authenticate('local')(req, res, () => {
					res.statusCode = 200;
					res.setHeader('Content-Type', 'application/json');
					res.json({
						success: true,
						status: 'Registration Successful!',
					});
				});
			}
		}
	);
});

router.post('/login', passport.authenticate('local'), (req, res) => {
	const token = authenticate.getToken({ _id: req.user._id }); // This will create a token for the user
	res.statusCode = 200;
	res.setHeader('Content-Type', 'application/json');
	res.json({
		success: true,
		token: token,
		status: 'You are successfully logged in!',
	});
});

router.get('/logout', (req, res, next) => {
	if (req.session) {
		req.session.destroy(); // This will delete the session information from the server side
		res.clearCookie('session-id'); // This will delete the session information from the client side
		res.redirect('/'); // This will redirect the user to the home page
	} else {
		const err = new Error('You are not logged in!');
		err.status = 401;
		return next(err);
	}
});

module.exports = router;
