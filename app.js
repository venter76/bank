
require('dotenv').config(); ggggg
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
    const conn = await mongoose.connect(`mongodb+srv://${db_username}:${db_password}@${db_cluster_url}/${db_name}?retryWrites=true&w=majority`, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useFindAndModify: false,
    });

    console.log('Connected to MongoDB Atlas:', conn.connection.host);
  } catch (error) {
    console.error('Error connecting to MongoDB Atlas:', error);
    process.exit(1);
  }
};




const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  verificationToken: String, // New field for verification token
  money: {
    type: Number,
    default: 100
  },
  resetPasswordToken: String, // Field for password reset token
  resetPasswordExpires: Date, // Field for token expiration time
  firstname: String,
  surname: String,
  dob: Date,
  date: {
    type: Date,
    default: Date.now
  },
  amount: {
    type: Number,
    default: 0,
  },
  role: {
    type: String,
    default: "user" 
  },
  newamount: Number
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

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
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

if (!process.env.ENCRYPTION_KEY || !process.env.IV) {
  encryptionKey = crypto.randomBytes(32).toString('hex');
  iv = crypto.randomBytes(16).toString('hex');

  // Log the values, so you can manually set them as environment variables later
  // console.log('ENCRYPTION_KEY:', encryptionKey);
  // console.log('IV:', iv);

  
} else {
  encryptionKey = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  iv = Buffer.from(process.env.IV, 'hex');
}

//End of encryption code.





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
      return res.redirect("/home2");
    });   
  })(req, res, next);
});






app.get("/welcome", function(req, res){
  res.render("welcome");
});


app.post('/welcome', (req, res) => {
  // Log req.session and req.user
  // console.log('req.session:', req.session);
  // console.log('req.user:', req.user);

  const { firstName, surname, dob } = req.body;

  if (!req.user) {
    res.status(400).send("You must be logged in to access this route.");
    return;
  }

  const userId = req.user._id;

  const dobString = dob.toString();

  // Encrypt the 'firstName' value
  const firstNameCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
  let encryptedFirstName = firstNameCipher.update(firstName, 'utf8', 'hex');
  encryptedFirstName += firstNameCipher.final('hex');

  // Encrypt the 'surname' value
  const surnameCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
  let encryptedSurname = surnameCipher.update(surname, 'utf8', 'hex');
  encryptedSurname += surnameCipher.final('hex');

  // Encrypt the 'dob' value
  const dobCipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
  let encryptedDob = dobCipher.update(dob, 'utf8', 'hex');
  encryptedDob += dobCipher.final('hex');

  // Decrypt the 'dob' value back into a date
  const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
  let decryptedDob = decipher.update(encryptedDob, 'hex', 'utf8');
  decryptedDob += decipher.final('utf8');

  User.findByIdAndUpdate(
    userId,
    {
      firstname: encryptedFirstName,
      surname: encryptedSurname,
      dob: new Date(decryptedDob),
    },
    { new: true },
    (err, user) => {
      if (err) {
        console.error(err);
        res.status(500).send("An error occurred while updating user information.");
        return;
      }

      // User information has been updated successfully
      // Redirect or render the next page here
      res.redirect('bank');
    }
  );
});


app.get('/register', function(req, res) {
  const errorMessage = req.query.error;
  res.render('register', { message: req.query.message, error: errorMessage });
});


app.post('/register', async function(req, res) {

  // Check if passwords match
  if (req.body.password !== req.body.passwordConfirm) {
    // Handle error: passwords do not match
    console.log('Passwords do not match');
    return res.redirect('/register'); // Use 'return' to exit the function immediately
  }

  try {
    const user = await User.register({ username: req.body.username, active: false }, req.body.password);

// 2. After user registration:
console.log("User registered:", user);


    // Generate a verification token
    const verificationToken = uuidv4();
    user.verificationToken = verificationToken;

// 3. Before saving user with token:
console.log("User with verification token:", user);

    await user.save();

    // 4. After user has been saved:
    console.log("User saved to DB:", user);

    // Send verification email
    const verificationLink = `${process.env.APP_URL}/verify?token=${verificationToken}`;

    const email = {
      from: 'brayroadapps@gmail.com',
      to: user.username,
      subject: 'Email Verification',
      text: `Please click the following link to verify your email address: ${verificationLink}`,
    };

    // 5. Email details:
    console.log("Email being sent:", email);

    try {
      await transporter.sendMail(email);
      console.log('Verification email sent');
      res.redirect('/register?message=verification'); // Redirect with success message
    } catch (mailErr) {
      console.log('Error sending mail:', mailErr);
      res.redirect('/register?error=mail'); // Redirect with an error message
    }

  } catch (err) {
    console.log(err);
    // Check if error is because user already exists
    if (err.name === 'UserExistsError') {
      return res.redirect('/register?error=User%20already%20exists.%20Select%20Login.');
    }
    return res.redirect('/home');
  }
});


app.get('/verify', function(req, res) {
  const verificationToken = req.query.token;
  
  // Find the user with the matching verification token
  User.findOne({ verificationToken: verificationToken })
    .then(user => {
      if (!user) {
        // Invalid or expired token
        console.log('Invalid or expired token');
        res.send('Unauthorized login');
        res.redirect('/');
      } else {
        // Update the user's verification status
        user.active = true;
        user.verificationToken = null; // Clear the verification token
        return user.save(); // Notice the 'return' here to chain the promise
      }
    })
    .then(() => {
      console.log('Email verified for user');
      res.redirect('/login');
    })
    .catch(err => {
      console.log(err);
      res.send('Unauthorized login');
      res.redirect('/');
    });
});



app.get('/forgotpassword', function(req, res) {
  let message = req.query.message;  // Extract message from the URL parameters.
  res.render('forgotpassword', { message: message });  // Pass message to the view.
});



app.post('/forgotpassword', function(req, res, next) {
  crypto.randomBytes(20, function(err, buf) {
    const token = buf.toString('hex');

    User.findOne({ username: req.body.username }, function(err, user) {
      if (!user) {
        // handle error: no user with this email
        console.log('No user with this email address');
        res.send("No user registered with this email address");
        res.redirect('/forgotpassword');
      }
      

      user.resetPasswordToken = token;
      user.resetPasswordExpires = Date.now() + 10800000; // 1 hour
      console.log(new Date(user.resetPasswordExpires));

      user.save(function(err) {
        if(err) {
          console.log(err);
          // handle error
          return res.redirect('/forgotpassword');
        }

        const mailOptions = {
          to: user.username,
          from: 'brayroadapps@gmail.com',
          subject: 'Node.js Password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };

        transporter.sendMail(mailOptions, function(error, info){
          if (error) {
            console.log(error);
            return res.redirect('/forgotpassword');
          } else {
            console.log('Email sent: ' + info.response);
            return res.redirect('/forgotpassword?message=Email%20has%20been%20sent%20with%20further%20instructions');
          }
        });
      });
    });
  });
});


app.get('/reset/:token', async function(req, res) {
  try {
    const user = await User.findOne({ 
      resetPasswordToken: req.params.token, 
      resetPasswordExpires: { $gt: Date.now() } 
    });

    if (!user) {
      // handle error: no user with this token, or token expired
      console.log('Password reset token is invalid or has expired.');
      return res.redirect('/forgotpassword?message=Password%20reset%20token%20is%20invalid%20or%20has%20expired');
    }

    // if user found, render a password reset form
    res.render('reset', {
      token: req.params.token
    });
  } catch (err) {
    console.error('Error in /reset/:token route:', err);
    res.status(500).send('Internal server error');
  }
});





app.post('/reset/:token', function(req, res) {
  User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
    if (!user) {
      console.log('Password reset token is invalid or has expired.');
      return res.redirect('/forgotpassword?message=Password%20reset%20token%20is%20invalid%20or%20has%20expired');
    }

    // Check if passwords match
    if (req.body.password !== req.body.passwordConfirm) {
      // Handle error: passwords do not match
      console.log('Passwords do not match');
      return res.redirect('/forgotpassword?message=Passwords%20do%20not%20match');
    } 

    user.setPassword(req.body.password, function(err) {
      if(err) {
        console.log(err);
        return res.redirect('/forgotpassword');
      }
      
      user.resetPasswordToken = undefined;
      user.resetPasswordExpires = undefined;

      user.save(function(err) {
        if(err) {
          console.log(err);
          return res.redirect('/forgotpassword');
        }
        // Log the user in and redirect them somewhere
        req.logIn(user, function(err) {
          res.redirect('/');
        });
      });
    });
  });
});




//Banking routes code:


app.get('/bank', ensureAuthenticated, function(req, res) {
  User.findById(req.user._id, function(err, user) {
    if (err) {
      console.log(err);
      // Handle the error accordingly
    } else {
      // Get the current date
      const now = new Date();

      // Calculate the difference in milliseconds
      const diffMs = now - user.date;

      // Convert to hours
      const diffHrs = diffMs / (1000 * 60 * 60);

      // Calculate the new amount
      // Calculate the new amount
      const newAmount = (user.money + (0.6 * diffHrs)).toFixed(2);
      
      // Update newamount field in user document
User.findByIdAndUpdate(req.user._id, { newamount: newAmount }, function(err, user) {
  if (err) {
    console.log(err);
    // Handle the error accordingly
  } else {
    // Success, do nothing
    console.log('User newamount updated successfully');

 
  }
});


      

// Decrypt the 'firstname' value using the existing 'crypto' setup
const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);


       // Decrypt the 'firstname' value
    let decryptedFirstname = decipher.update(user.firstname, 'hex', 'utf8');
    decryptedFirstname += decipher.final('utf8');

      res.render('bank', { money: newAmount,  amount: user.amount, firstname: decryptedFirstname, error: req.flash('error')});
    
    }
  });
});



app.get('/transact', ensureAuthenticated, ensureAdmin, function(req, res)  {

// Decrypt function
function decrypt(text){
  let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(process.env.ENCRYPTION_KEY, 'hex'), Buffer.from(process.env.IV, 'hex'));
  let decrypted = decipher.update(text, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}


  // Query the database to get all users
  User.find({}, (err, users) => {
    if (err) {
      console.log(err);
      res.status(500).send("Error occurred while fetching users");
    } else {

       // Filter out users without a firstname
    const usersWithFirstnames = users.filter(user => user.firstname);


    
// Decrypt the firstnames
const firstnames = usersWithFirstnames.map(user => decrypt(user.firstname));
const newamounts = usersWithFirstnames.map(user => user.newamount);

      
      
      // Render the transact view with the firstnames
      res.render('transact', { firstnames, newamounts });

    }
  });
});


app.get('/transact/:firstname', ensureAuthenticated, ensureAdmin, (req, res) => {
  // The selected firstname is available as req.params.firstname
  const selectedFirstname = req.params.firstname;
  console.log(selectedFirstname);

 
  res.render('transact2', { firstname: selectedFirstname });
});


app.post('/transact2', ensureAuthenticated, ensureAdmin, (req, res) => {
  const { debit, credit, firstname } = req.body;
  console.log(firstname);

  // Encrypt the firstname
  const firstname2Cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
  let encrypteddFirstname = firstname2Cipher.update(firstname, 'utf8', 'hex');
  encrypteddFirstname += firstname2Cipher.final('hex');

  


  console.log(encrypteddFirstname);

  // Convert the debit and credit amounts to numbers
  const debitAmount = parseInt(debit) || 0;
  const creditAmount = parseInt(credit) || 0;

  // Find the user by firstname
  User.findOne({ firstname: encrypteddFirstname }, (err, user) => {
    if (err) {
      // Handle the error
      return res.status(500).send('Internal Server Error');
    }

    if (!user) {
      // Handle the case if the user is not found
      return res.status(404).send('User not found');
    }

     // Update the amount based on the debit and credit amounts
     user.amount = user.amount + debitAmount - creditAmount;

   // Save the updated user object
   user.save((err) => {
    if (err) {
      // Handle the error
      return res.status(500).send('Internal Server Error');
    }

    // If successful, redirect or render as needed
    res.redirect('/logout'); // or res.render(), depending on your need
  });
});
});




app.get('/logout', ensureAuthenticated, function(req, res) {
  User.findById(req.user._id, function(err, user) {
    if (err) {
      console.log(err);
      // Handle the error accordingly
    } else {
     // Decrypt the 'firstname' value using the existing 'crypto' setup
          const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);


      // Decrypt the 'firstname' value
        let decryptedFirstname = decipher.update(user.firstname, 'hex', 'utf8');
        decryptedFirstname += decipher.final('utf8');


      res.render('logout', { firstname: decryptedFirstname});
    }
  });
});




connectDB().then(() => {
  app.listen(PORT, () => {
      console.log("listening for requests");
  })
})






//END