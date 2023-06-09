const express = require('express');
const authenticate = require('../authenticate');
const multer = require('multer');
const cors = require('./cors');

const storage = multer.diskStorage({
	destination: (req, file, cb) => {
		// cb = callback
		cb(null, 'public/images'); // null = no error
	},
	filename: (req, file, cb) => {
		cb(null, file.originalname); // null = no error
	},
});

const imageFileFilter = (req, file, cb) => {
	if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
		// regex
		return cb(new Error('You can upload only image files!'), false);
	}
	cb(null, true);
};

const upload = multer({ storage: storage, fileFilter: imageFileFilter }); // storage = storage object, fileFilter = imageFileFilter function

const uploadRouter = express.Router();

uploadRouter
	.route('/')
	.options(cors.corsWithOptions, (req, res) => res.sendStatus(200)) // corsWithOptions = corsWithOptions function, (req, res) => res.sendStatus(200) = send status code 200
	.get(
		cors.cors,
		authenticate.verifyUser,
		authenticate.verifyAdmin,
		(req, res, next) => {
			// authenticate.verifyUser = verify user, authenticate.verifyAdmin = verify admin
			res.statusCode = 403;
			res.end('GET operation not supported on /imageUpload');
		}
	)
	.post(
		cors.corsWithOptions,
		authenticate.verifyUser,
		authenticate.verifyAdmin,
		upload.single('imageFile'),
		(req, res) => {
			// authenticate.verifyUser = verify user, authenticate.verifyAdmin = verify admin, upload.single('imageFile') = upload single image file
			res.statusCode = 200;
			res.setHeader('Content-Type', 'application/json');
			res.json(req.file); // req.file = file object
		}
	)
	.put(
		cors.corsWithOptions,
		authenticate.verifyUser,
		authenticate.verifyAdmin,
		(req, res, next) => {
			// authenticate.verifyUser = verify user, authenticate.verifyAdmin = verify admin
			res.statusCode = 403;
			res.end('PUT operation not supported on /imageUpload');
		}
	)
	.delete(
		cors.corsWithOptions,
		authenticate.verifyUser,
		authenticate.verifyAdmin,
		(req, res, next) => {
			// authenticate.verifyUser = verify user, authenticate.verifyAdmin = verify admin
			res.statusCode = 403;
			res.end('DELETE operation not supported on /imageUpload');
		}
	);

module.exports = uploadRouter; // export uploadRouter module
