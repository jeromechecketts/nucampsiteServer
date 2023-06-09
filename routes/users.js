const express = require('express');
const passport = require('passport');
const authenticate = require('../authenticate');
const users = require('../models/users');
const cors = require('./cors');

const User = require('../models/users');

const router = express.Router();

/* GET users listing. */
router.get(
	'/',
	cors.corsWithOptions,
	authenticate.verifyUser,
	authenticate.verifyAdmin,
	function (req, res, next) {
		users
			.find()
			.then((users) => {
				res.json(users);
			})
			.catch((err) => next(err));
	}
);

router.post('/signup', cors.corsWithOptions, (req, res) => {
	User.register(
		new User({ username: req.body.username }), // This is the username
		req.body.password, // This is the password
		(err, user) => {
			if (err) {
				res.statusCode = 500;
				res.setHeader('Content-Type', 'application/json');
				res.json({ err: err });
			} else {
				if (req.body.firstname) {
					user.firstname = req.body.firstname;
				}
				if (req.body.lastname) {
					user.lastname = req.body.lastname;
				}
				user.save((err) => {
					if (err) {
						res.statusCode = 500;
						res.setHeader('Content-Type', 'application/json');
						res.json({ err: err });
						return;
					}
					passport.authenticate('local')(req, res, () => {
						res.statusCode = 200;
						res.setHeader('Content-Type', 'application/json');
						res.json({
							success: true,
							status: 'Registration Successful!',
						});
					});
				});
			}
		}
	);
});

router.post(
	'/login',
	cors.corsWithOptions,
	passport.authenticate('local'),
	(req, res) => {
		const token = authenticate.getToken({ _id: req.user._id }); // This will create a token for the user
		res.statusCode = 200;
		res.setHeader('Content-Type', 'application/json');
		res.json({
			success: true,
			token: token,
			status: 'You are successfully logged in!',
		});
	}
);

router.get('/logout', cors.corsWithOptions, (req, res, next) => {
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

router.get(
	'/facebook/token',
	passport.authenticate('facebook-token'),
	(req, res) => {
		if (req.user) {
			const token = authenticate.getToken({ _id: req.user._id }); // This will create a token for the user
			res.statusCode = 200;
			res.setHeader('Content-Type', 'application/json');
			res.json({
				success: true,
				token: token,
				status: 'You are successfully logged in!',
			});
		}
	}
);

module.exports = router;
