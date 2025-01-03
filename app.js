
require('dotenv').config(); 
const express = require("express");
const bodyParser = require("body-parser");
const ensureAuthenticated = require('./authMiddleware'); 
const ensureAdmin = require('./ensureAdmin');
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const schedule = require('node-schedule');
const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const flash = require('connect-flash');
const MongoStore = require('connect-mongo');
const cron = require('node-cron');



//Nodemailer setup for email verification:


const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,
    pass: process.env.EMAIL_PASSWORD
  }
});


transporter.verify(function (error, success) {
  if(error) {
      console.log(error);
  } else {
      console.log('Server validation done and ready for messages.')
  }
});



const app = express();
const PORT = process.env.PORT || 3000
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));




//MongoDB setup:



const db_username = process.env.DB_USERNAME;
const db_password = process.env.DB_PASSWORD;
const db_cluster_url = process.env.DB_CLUSTER_URL;
const db_name = process.env.DB_NAME;


const connectDB = async () => {
  try {
    const conn = await mongoose.connect(
      `mongodb+srv://${db_username}:${db_password}@${db_cluster_url}/${db_name}?retryWrites=true&w=majority`, 
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );

    console.log('Connected to MongoDB Atlas:', conn.connection.host);
  } catch (error) {
    console.error('Error connecting to MongoDB Atlas:', error.message);
    process.exit(1);
  }
};





const userSchema = new mongoose.Schema({
  email: String,
  password: String, // Stored as a hash using passport-local-mongoose
  verificationToken: String, // Field for email verification token
  resetPasswordToken: String, // Field for password reset token
  resetPasswordExpires: Date, // Expiry time for password reset token
  firstname: String, // User's first name
  surname: String, // User's surname
  dob: Date, // Date of birth
  money: {
    type: Number,
    default: 100, // Initial account balance
  },
  lastUpdated: {
    type: Date,
    default: Date.now, // Tracks when the balance was last updated
  },
  date: {
    type: Date,
    default: Date.now, // User's account creation date
  },
  role: {
    type: String,
    default: "user", // Role of the user (e.g., "user", "admin")
  },
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

module.exports = User;



//Session cookie setup:

app.set('trust proxy', 1);

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: `mongodb+srv://${db_username}:${db_password}@${db_cluster_url}/${db_name}?retryWrites=true&w=majority`,
    }),
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    httpOnly: true, // prevents JavaScript from making changes
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));





app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
  try {
    const user = await User.findById(id); // User is your Mongoose model
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});




// Middleware to log the user object (just for debugging purposes):

// app.use((req, res, next) => {
//   console.log(req.user);
//   next();
// });



// These lines are to encrypt personal data in database (NOT login data or password):
  
const algorithm = process.env.ALGORITHM;


let encryptionKey;
let iv;

// Load encryptionKey and iv from environment variables
if (process.env.ENCRYPTION_KEY && process.env.IV) {
  encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  iv = Buffer.from(process.env.IV, 'hex');
} else {
  console.error('Encryption key and IV must be set as environment variables.');
  process.exit(1); // Exit the process if these variables are not set
}

//End of encryption code.


// Job to update user balances every 2 minutes
cron.schedule('*/2 * * * *', async () => { 
  try {
    console.log('Running 2-minute balance update...');

    const incrementAmount = 120; // Increment amount per 2 minutes
    const now = new Date();

    // Find all users
    const users = await User.find({});

    for (const user of users) {
      // Calculate the number of 2-minute intervals since the last update
      const diffMs = now - user.lastUpdated;
      const diffIntervals = Math.floor(diffMs / (1000 * 60 * 2)); // 2 minutes per interval

      if (diffIntervals > 0) {
        // Update the balance
        user.money += diffIntervals * incrementAmount;

        // Update the lastUpdated field
        user.lastUpdated = now;

        // Save the updated user
        await user.save();

        console.log(`Updated balance for user ${user.firstname}: ${user.money}`);
      }
    }

    console.log('2-minute balance update complete.');
  } catch (err) {
    console.error('Error running 2-minute balance update:', err);
  }
});



//Authentication Routes code:




app.get("/", function(req, res){
  res.render("home");
});


app.get("/login", function(req, res){
  res.render("login", { message: req.query.message });
});


app.post("/login", function(req, res, next) {
  passport.authenticate("local", function(err, user, info) {
    if (err) {
      console.log(err);
      return next(err); // Pass the error to the next middleware
    }

    if (!user) {
      // Authentication failed, redirect back to the login page
      return res.redirect("/login?message=Incorrect%20username%20or%20password");
    }

    if (user.verificationToken !== null) {
      console.log("No user found");
      return res.redirect("/login?message=Email%20not%20verified");
    }

    req.login(user, function(err) {
      if (err) {
        console.log(err);
        return next(err); // Pass the error to the next middleware
      }

      // If it's the user's first login (indicated by no firstname), redirect to the welcome page.
      if (!user.firstname) {
        return res.redirect("/welcome");
      }

      // If it's not the user's first login, redirect to their main page.
      return res.redirect("/bank");
    });   
  })(req, res, next);
});






app.get("/welcome", function(req, res){
  res.render("welcome");
});


app.post('/welcome', async (req, res) => {
  const { firstName, surname, dob } = req.body;

  if (!req.user) {
    res.status(400).send('You must be logged in to access this route.');
    return;
  }

  try {
    const userId = req.user._id;

    // Encrypt firstName
    const firstNameCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
    let encryptedFirstName = firstNameCipher.update(firstName, 'utf8', 'hex');
    encryptedFirstName += firstNameCipher.final('hex');

    // Encrypt surname
    const surnameCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
    let encryptedSurname = surnameCipher.update(surname, 'utf8', 'hex');
    encryptedSurname += surnameCipher.final('hex');

    // Encrypt dob
    const dobCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
    let encryptedDob = dobCipher.update(dob, 'utf8', 'hex');
    encryptedDob += dobCipher.final('hex');

    // Decrypt dob to ensure it's stored as a valid Date
    const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
    let decryptedDob = decipher.update(encryptedDob, 'hex', 'utf8');
    decryptedDob += decipher.final('utf8');

    // Update user in the database
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      {
        firstname: encryptedFirstName,
        surname: encryptedSurname,
        dob: new Date(decryptedDob), // Convert decrypted dob to Date object
      },
      { new: true }
    );

    if (!updatedUser) {
      throw new Error('User not found');
    }

    res.redirect('/bank');
  } catch (err) {
    console.error('Error in /welcome route:', err);
    res.status(500).send('An error occurred while updating user information.');
  }
});

app.get('/register', (req, res) => {
  const errorMessage = req.query.error;
  res.render('register', { message: req.query.message, error: errorMessage });
});

app.post('/register', async (req, res) => {
  if (req.body.password !== req.body.passwordConfirm) {
    console.log('Passwords do not match');
    return res.redirect('/register');
  }

  try {
    const user = await User.register({ username: req.body.username, active: false }, req.body.password);

    const verificationToken = uuidv4();
    user.verificationToken = verificationToken;
    await user.save();

    const verificationLink = `${process.env.APP_URL}/verify?token=${verificationToken}`;

    const email = {
      from: 'brayroadapps@gmail.com',
      to: user.username,
      subject: 'Email Verification',
      text: `Please click the following link to verify your email address: ${verificationLink}`,
    };

    await transporter.sendMail(email);
    console.log('Verification email sent');
    res.redirect('/register?message=verification');
  } catch (err) {
    console.error(err);
    if (err.name === 'UserExistsError') {
      return res.redirect('/register?error=User%20already%20exists.%20Select%20Login.');
    }
    res.redirect('/home');
  }
});

app.get('/verify', async (req, res) => {
  const verificationToken = req.query.token;

  try {
    const user = await User.findOne({ verificationToken });
    if (!user) {
      console.log('Invalid or expired token');
      return res.redirect('/');
    }

    user.active = true;
    user.verificationToken = null;
    await user.save();

    console.log('Email verified for user');
    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.redirect('/');
  }
});

app.get('/forgotpassword', function(req, res) {
  const message = req.query.message; // Extract message from the URL parameters
  res.render('forgotpassword', { message: message }); // Pass the message to the view
});


app.post('/forgotpassword', async (req, res) => {
  try {
    const token = crypto.randomBytes(20).toString('hex');
    const user = await User.findOne({ username: req.body.username });

    if (!user) {
      console.log('No user with this email address');
      return res.redirect('/forgotpassword');
    }

    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 10800000;
    await user.save();

    const mailOptions = {
      to: user.username,
      from: 'brayroadapps@gmail.com',
      subject: 'Node.js Password Reset',
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
        `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
        `http://${req.headers.host}/reset/${token}\n\n` +
        `If you did not request this, please ignore this email and your password will remain unchanged.\n`,
    };

    await transporter.sendMail(mailOptions);
    res.redirect('/forgotpassword?message=Email%20has%20been%20sent%20with%20further%20instructions');
  } catch (err) {
    console.error(err);
    res.redirect('/forgotpassword');
  }
});

app.get('/reset/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      console.log('Password reset token is invalid or has expired.');
      return res.redirect('/forgotpassword?message=Password%20reset%20token%20is%20invalid%20or%20has%20expired');
    }

    res.render('reset', { token: req.params.token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Internal server error');
  }
});

app.post('/reset/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      console.log('Password reset token is invalid or has expired.');
      return res.redirect('/forgotpassword?message=Password%20reset%20token%20is%20invalid%20or%20has%20expired');
    }

    if (req.body.password !== req.body.passwordConfirm) {
      console.log('Passwords do not match');
      return res.redirect('/forgotpassword?message=Passwords%20do%20not%20match');
    }

    user.setPassword(req.body.password, async (err) => {
      if (err) {
        console.error(err);
        return res.redirect('/forgotpassword');
      }

      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;
      await user.save();

      req.logIn(user, (err) => {
        if (err) {
          console.error(err);
          return res.redirect('/forgotpassword');
        }

        res.redirect('/');
      });
    });
  } catch (err) {
    console.error(err);
    res.redirect('/forgotpassword');
  }
});


app.get('/bank', ensureAuthenticated, async function (req, res) {
  try {
    // Find the user by ID
    const user = await User.findById(req.user._id);

    if (!user) {
      req.flash('error', 'User not found');
      return res.redirect('/login');
    }

    // Decrypt the 'firstname' value
    const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
    let decryptedFirstname = decipher.update(user.firstname, 'hex', 'utf8');
    decryptedFirstname += decipher.final('utf8');

    // Render the bank page
    res.render('bank', { 
      money: user.money, // Current balance from the database
      firstname: decryptedFirstname, // Decrypted firstname
      error: req.flash('error') // Error messages, if any
    });
  } catch (err) {
    console.error('Error in /bank route:', err);
    req.flash('error', 'An error occurred');
    res.redirect('/login');
  }
});


app.get('/transact', ensureAuthenticated, ensureAdmin, async (req, res) => {
  try {
    // Query the database to get all users
    const users = await User.find({});

    // Decrypt the firstnames of the users
    const decryptedFirstnames = users.map(user => {
      try {
        const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
        let decrypted = decipher.update(user.firstname, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
      } catch (err) {
        console.error(`Error decrypting firstname for user ${user._id}:`, err);
        return "Unknown"; // Fallback in case decryption fails
      }
    });

    // Render the transact view with the decrypted firstnames
    res.render('transact', { firstnames: decryptedFirstnames });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error occurred while fetching users");
  }
});



app.get('/transact/:firstname', ensureAuthenticated, ensureAdmin, (req, res) => {
  // The selected firstname is available as req.params.firstname
  const selectedFirstname = req.params.firstname;
  console.log('Selected firstname for transact2:', selectedFirstname);
  // Render the transact2 view with the selected firstname
  res.render('transact2', { firstname: selectedFirstname });
});




app.post('/transact2', async (req, res) => {
  const { debit, credit, firstname } = req.body;

  try {
    console.log('Received firstname in POST /transact2:', firstname);

    // Encrypt the firstname to match the stored value in the database
    const firstnameCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
    let encryptedFirstname = firstnameCipher.update(firstname, 'utf8', 'hex');
    encryptedFirstname += firstnameCipher.final('hex');

    console.log('Encrypted firstname for query:', encryptedFirstname);

    // Find the user by the encrypted firstname
    const user = await User.findOne({ firstname: encryptedFirstname });

    if (!user) {
      console.error('User not found for firstname:', encryptedFirstname);
      return res.status(404).send('User not found');
    }

    // Calculate the new amount
    const debitAmount = parseInt(debit, 10) || 0;
    const creditAmount = parseInt(credit, 10) || 0;
    const newAmount = user.amount + debitAmount - creditAmount;

    // Update the user's amount
    user.amount = newAmount;
    await user.save();

    console.log(`Debited: ${debitAmount}, Credited: ${creditAmount}, New Amount: ${newAmount}`);

    // Render the bank page with both money and amount
    res.render('bank', { money: newAmount, amount: user.amount, firstname, error: [] });
  } catch (err) {
    console.error(err);
    res.status(500).render('bank', { money: null, amount: null, firstname: null, error: ['Internal Server Error'] });
  }
});







connectDB().then(() => {
  app.listen(PORT, () => {
    console.log("listening for requests");
  });
});
