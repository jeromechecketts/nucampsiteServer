const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/users');

const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const jwt = require('jsonwebtoken'); // Used to create, sign, and verify tokens

const config = require('./config.js');

exports.local = passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

exports.getToken = function (user) {
	return jwt.sign(user, config.secretKey, { expiresIn: 3600 });
};

const opts = {}; // Options for the JWT strategy
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken(); // Extract the JWT from the header of the incoming request
opts.secretOrKey = config.secretKey; // The secret key used to sign the JWT

exports.jwtPassport = passport.use(
	new JwtStrategy(opts, (jwt_payload, done) => {
		console.log('JWT payload:', jwt_payload);
		User.findOne({ _id: jwt_payload._id }, (err, user) => {
			// Search for the user in the database})
			if (err) {
				return done(err, false); // If there is an error, return done with the error and false
			} else if (user) {
				return done(null, user); // If the user is found, return done with no error and the user
			} else {
				return done(null, false); // If the user is not found, return done with no error and false
			}
		});
	})
);

exports.verifyUser = passport.authenticate('jwt', { session: false }); // This will verify the user's JWT
