const createError = require('http-errors');
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const logger = require('morgan');

const indexRouter = require('./routes/index');
const usersRouter = require('./routes/users');
const campsiteRouter = require('./routes/campsiteRouter');
const promotionRouter = require('./routes/promotionRouter');
const partnerRouter = require('./routes/partnerRouter');
const uploadRouter = require('./routes/uploadRouter');
const favoriteRouter = require('./routes/favoriteRouter');

const mongoose = require('mongoose');

const passport = require('passport');
const authenticate = require('./authenticate');
const config = require('./config');

const url = config.mongoUrl;
const connect = mongoose.connect(url, {
	useCreateIndex: true,
	useFindAndModify: false,
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

connect.then(
	() => console.log('Connected correctly to server'),
	(err) => console.log(err)
);

const app = express();

app.all('*', (req, res, next) => {
	if (req.secure) {
		return next();
	} else {
		console.log(
			`Redirecting to: https://${req.hostname}:${app.get('secPort')}${
				req.url
			}`
		);
		res.redirect(
			301,
			`https://${req.hostname}:${app.get('secPort')}${req.url}`
		);
	}
});

const session = require('express-session');
const FileStore = require('session-file-store')(session);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
// app.use(cookieParser('12345-67890-09876-54321'));

app.use(
	session({
		name: 'session-id',
		secret: '12345-67890-09876-54321',
		saveUninitialized: false,
		resave: false,
		store: new FileStore(),
	})
);

app.use(passport.initialize());
app.use(passport.session());

app.use('/', indexRouter);
app.use('/users', usersRouter);

// function auth(req, res, next) {
// 	console.log(req.user);

// 	if (!req.user) {
// 		const err = new Error('You are not authenticated!');
// 		err.status = 401;
// 		return next(err);
// 	} else {
// 		return next();
// 	}
// }

// app.use(auth);
app.use(express.static(path.join(__dirname, 'public')));

app.use('/campsites', campsiteRouter); // This is the route for the campsiteRouter
app.use('/promotions', promotionRouter); // This is the route for the promotionRouter
app.use('/partners', partnerRouter); // This is the route for the partnerRouter
app.use('/imageUpload', uploadRouter); // This is the route for the uploadRouter
app.use('/favorites', favoriteRouter); // This is the route for the favoriteRouter

// catch 404 and forward to error handler
app.use(function (req, res, next) {
	next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
	// set locals, only providing error in development
	res.locals.message = err.message;
	res.locals.error = req.app.get('env') === 'development' ? err : {};

	// render the error page
	res.status(err.status || 500);
	res.render('error');
});

module.exports = app;
