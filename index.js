const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const passwordValidator = require('password-validator');
const loginAttempts = new Map();
const maxRetries = 5;
const cooldownPeriod = 60000; // 1 minute in milliseconds
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const uri = "mongodb+srv://Jijul:Zzul2501@cluster0.ta9gou3.mongodb.net/";

const passwordSchema = new passwordValidator();
passwordSchema
  .is().min(8)            // Minimum length 8
  .is().max(100)          // Maximum length 100
  .has().uppercase()      // Must have uppercase letters
  .has().lowercase()      // Must have lowercase letters
  .has().digits()         // Must have digits
  .has().not().spaces();   // Should not have spaces


const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Welcome to web app Secure Info',
            version: '1.0.0'
        },
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
    customCss: '.swagger-ui .topbar { background-color: #00827F; } body { background-color: #CFECEC; }',
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { customCss: options.customCss }));

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


async function run() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  console.log("You successfully connected to MongoDB!");

  app.use(express.json());
  app.listen(port, () => {
    console.log(`Server listening at http://localSecurity:${port}`);
  });

  app.get('/', (req, res) => {
    res.send('Server Group 21 Information Security');
  });

  /**
 * @swagger
 * /registerAdmin:
 *   post:
 *     summary: Register an admin
 *     description: Register a new admin with username, password, name, email, phoneNumber, and role
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *               role:
 *                 type: string
 *                 enum: [Admin]
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Admin registered successfully
 *       '400':
 *         description: Username already registered
 */
  
  app.post('/registerAdmin', async (req, res) => {
    let data = req.body;
    res.send(await registerAdmin(client, data));
  });

  /**
 * @swagger
 * /loginAdmin:
 *   post:
 *     summary: Login as admin
 *     description: Authenticate and log in as admin with username and password, and receive a token
 *     tags:
 *       - Admin
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the admin
 *               password:
 *                 type: string
 *                 description: The password of the admin
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Admin login successful, provides a token
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post('/loginAdmin', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data, 'Admin')); // Specify role as 'Admin'
});


  /**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Login as a security user
 *     description: Login as a security user with username and password
 *     tags:
 *       - Security
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security user
 *               password:
 *                 type: string
 *                 description: The password of the security user
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Login successful
 *       '401':
 *         description: Unauthorized - Invalid username or password
 */
app.post('/loginSecurity', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data, 'Security')); // Specify role as 'Security'
});


  /**
 * @swagger
 * /registerSecurity:
 *   post:
 *     summary: Register a new security user
 *     description: Register a new security user with username, password, name, email, and phoneNumber
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the security
 *               password:
 *                 type: string
 *                 description: The password of the security
 *               name:
 *                 type: string
 *                 description: The name of the security
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the security
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the security
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Security user registered successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */

  app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

  
  /**
 * @swagger
 * /readAdmin:
 *   get:
 *     summary: Read admin data
 *     description: Retrieve admin data using a valid token obtained from loginAdmin
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Admin data retrieval successful
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with admin access
 */
  app.get('/readAdmin', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  /**
 * @swagger
 * /readSecurity:
 *   get:
 *     summary: Read security user data
 *     description: Read security user data with a valid token obtained from the loginSecurity endpoint
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Security user data retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Security user not found
 */
  app.get('/readSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  /**
 * @swagger
 * /registerHost:
 *   post:
 *     summary: Register a new host
 *     description: Register a new host with username, password, name, email, and phoneNumber
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *               name:
 *                 type: string
 *                 description: The name of the host
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the host
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the host
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Host registered successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid or user is not a security user
 *       '400':
 *         description: Username already in use, please enter another username
 */

  app.post('/registerHost', verifyToken, async (req, res) => {
    let data = req.user;
    let hostData = req.body;
    res.send(await registerHost(client, data, hostData));
});


  /**
 * @swagger
 * /VisitorPass:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Issue a new visitor pass with a valid token obtained from loginHost
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               visitorUsername:
 *                 type: string
 *                 description: The username of the visitor for whom the pass is issued
 *               phoneNumber:
 *                 type: string
 *                 description: Additional details for the pass (optional)
 *             required:
 *               - visitorUsername
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully, returns a unique pass identifier
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Visitor not found
 */
app.post('/VisitorPass', verifyToken, async (req, res) => {
    let data = req.user;
    let passData = req.body;
    res.send(await VisitorPass(client, data, passData));
});

/**
 * @swagger
 * /retrievePass/{passIdentifier}:
 *   get:
 *     summary: Retrieve visitor pass details
 *     description: Retrieve pass details for a visitor using the pass identifier
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique pass identifier
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Visitor pass details retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */
app.get('/retrievePass/:passIdentifier', verifyToken, async (req, res) => {
    let data = req.user;
    let passIdentifier = req.params.passIdentifier;
    res.send(await retrievePass(client, data, passIdentifier));
});

/**
 * @swagger
 * /retrieveContactNumber/{passIdentifier}:
 *   get:
 *     summary: Retrieve host name and contact from visitor pass
 *     description: Retrieve the host name and contact associated with the given visitor pass (Only accessible by authenticated security user)
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: passIdentifier
 *         required: true
 *         description: The unique pass identifier
 *         schema:
 *           type: string
 *     responses:
 *       '200':
 *         description: Host name and contact retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with security access
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */

app.get('/retrieveContactNumber/:passIdentifier', verifySecurityToken, async (req, res) => {
    let data = req.user;
    let passIdentifier = req.params.passIdentifier;
    res.send(await retrieveHostContact(client, data, passIdentifier));
});

// New middleware function to verify security token
function verifySecurityToken(req, res, next) {
    let header = req.headers.authorization;

    if (!header) {
        return res.status(401).send('Unauthorized');
    }

    let token = header.split(' ')[1];

    jwt.verify(token, 'julpassword', function (err, decoded) {
        if (err) {
            console.error(err);
            return res.status(401).send('Invalid token');
        }

        // Check if the role is 'Security'
        if (decoded.role !== 'Security') {
            return res.status(403).send('Forbidden - Token is not associated with security access');
        }

        req.user = decoded;
        next();
    });
}

/**
 * @swagger
 * /loginHost:
 *   post:
 *     summary: Login as a host
 *     description: Authenticate and log in as a host with username and password, and receive a token
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Host login successful, provides a token
 *       '401':
 *         description: Unauthorized - Invalid credentials
 */
app.post('/loginHost', async (req, res) => {
    let data = req.body;
    res.send(await login(client, data, 'Host'));
});

/**
 * @swagger
 * /deleteUser/{username}:
 *   delete:
 *     summary: Delete a user (security, host, or visitor)
 *     description: Delete a user with a valid token obtained from loginAdmin
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: username
 *         required: true
 *         description: The username of the user to be deleted
 *         schema:
 *           type: string
 *       - in: query
 *         name: role
 *         required: true
 *         description: The role of the user to be deleted (Security, Host, or Visitor)
 *         schema:
 *           type: string
 *           enum: [Security, Host, Visitor]
 *     responses:
 *       '200':
 *         description: User deleted successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with admin access
 *       '404':
 *         description: User not found
 */
app.delete('/deleteUser/:username', verifyToken, async (req, res) => {
    let data = req.user;
    let usernameToDelete = req.params.username;
    let roleToDelete = req.query.role;

    if (!['Security', 'Host', 'Visitor'].includes(roleToDelete)) {
        return res.status(400).send('Invalid role specified');
    }

    res.send(await deleteUser(client, data, usernameToDelete, roleToDelete));
});

/**
 * @swagger
 * /readHost:
 *   get:
 *     summary: Read host data and visitor passes
 *     description: Retrieve host data and visitor passes using a valid token obtained from loginHost
 *     tags:
 *       - Host
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Host data and visitor passes retrieval successful
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
app.get('/readHost', verifyToken, async (req, res) => {
    let data = req.user;
    const hostData = await readHost(client, data);
    res.send(hostData);
});

/**
 * @swagger
 * /registerHostWithoutApproval:
 *   post:
 *     summary: Register a new host without security approval
 *     description: Register a new host without waiting for security approval with username, password, name, email, and phoneNumber
 *     tags:
 *       - Host
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The username of the host
 *               password:
 *                 type: string
 *                 description: The password of the host
 *               name:
 *                 type: string
 *                 description: The name of the host
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The email of the host
 *               phoneNumber:
 *                 type: string
 *                 description: The phone number of the host
 *             required:
 *               - username
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Host registered successfully without security approval
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */

app.post('/registerHostWithoutApproval', async (req, res) => {
    let hostData = req.body;
    res.send(await registerHostWithoutApproval(client, hostData));
});

}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'julpassword',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

// Function to register admin
async function registerAdmin(client, data) {
    data.password = await encryptPassword(data.password);
    
    const adminCollection = client.db("assigment").collection("Admin");
  
    // Check if an admin already exists
    const existingAdmin = await adminCollection.findOne({ role: 'Admin' });
  
    if (existingAdmin) {
      return 'An admin is already registered';
    }
  
    // Validate the strength of the password
    const passwordValidationResult = validateStrongPassword(data.password);
  
    if (passwordValidationResult !== 'Password is strong.') {
      return passwordValidationResult;
    }
  
    const result = await adminCollection.insertOne(data);
    return 'Admin registered';
  }
  
//Function to login
async function login(client, data, role) {
    const adminCollection = client.db("assigment").collection("Admin");
    const securityCollection = client.db("assigment").collection("Security");
    const hostCollection = client.db("assigment").collection("Host");

    let match;

    if (role === 'Admin') {
        match = await adminCollection.findOne({ username: data.username });
    } else if (role === 'Security') {
        match = await securityCollection.findOne({ username: data.username });
    } else if (role === 'Host') {
        match = await hostCollection.findOne({ username: data.username });
    }

    if (match) {
        // Compare the provided password with the stored password
        const isPasswordMatch = await decryptPassword(data.password, match.password);

        if (isPasswordMatch) {
            console.clear(); // Clear the console
            const token = generateToken(match);
            console.log(output(match.role));
            return "\nToken for " + match.name + ": " + token;
        } else {
            return "Wrong password";
        }
    } else {
        return "User not found";
    }
}
// Function to login
async function login(client, data, role) {
    const adminCollection = client.db("assigment").collection("Admin");
    const securityCollection = client.db("assigment").collection("Security");
    const hostCollection = client.db("assigment").collection("Host");

    // Check if the account is temporarily locked
    const lockedUntil = loginAttempts.get(data.username);
    if (lockedUntil && lockedUntil > Date.now()) {
        const remainingTime = (lockedUntil - Date.now()) / 1000;
        console.log(`Too many unsuccessful login attempts. Account locked. Please wait for ${remainingTime} seconds.`);
        return "Login failed";
    }

    let match;

    if (role === 'Admin') {
        match = await adminCollection.findOne({ username: data.username });
    } else if (role === 'Security') {
        match = await securityCollection.findOne({ username: data.username });
    } else if (role === 'Host') {
        match = await hostCollection.findOne({ username: data.username });
    }

    if (match) {
        // Compare the provided password with the stored password
        const isPasswordMatch = await decryptPassword(data.password, match.password);

        if (isPasswordMatch) {
            console.clear(); // Clear the console
            const token = generateToken(match);
            console.log(output(match.role));
            // Reset login attempts on successful login
            loginAttempts.delete(data.username);
            return "\nToken for " + match.name + ": " + token;
        } else {
            // Increment login attempts for unsuccessful login
            const attempts = loginAttempts.get(data.username) || 0;

            if (attempts >= maxRetries - 1) {
                // Lock the account if maximum retries reached
                loginAttempts.set(data.username, Date.now() + cooldownPeriod);
                console.log(`Too many unsuccessful login attempts. Account locked. Please wait for ${cooldownPeriod / 1000} seconds.`);
                return "Login failed";
            } else {
                loginAttempts.set(data.username, attempts + 1);
                if (attempts === maxRetries - 1) {
                    console.log(`Too many unsuccessful login attempts. Account will be locked after this attempt.`);
                }
                return `Wrong password. Remaining attempts: ${maxRetries - attempts - 1}`;
            }
        }
    } else {
        return "User not found";
    }
}

//Function to encrypt password
async function encryptPassword(password) {
  const hash = await bcrypt.hash(password, saltRounds); 
  return hash 
}

//Function to decrypt password
async function decryptPassword(password, compare) {
  const match = await bcrypt.compare(password, compare)
  return match
}

// Function to register host
async function registerHost(client, data, hostData) {
    const securityCollection = client.db("assigment").collection("Security");
    const hostCollection = client.db("assigment").collection("Host");
  
    // Check if the user is a security user
    if (data.role !== "Security") {
      return "Unauthorized - Only security users can register hosts";
    }
  
    const tempHost = await hostCollection.findOne({ username: hostData.username });
  
    if (tempHost) {
      return "Username already in use, please enter another username";
    }
  
    // Validate the strength of the password
    const passwordValidationResult = validateStrongPassword(hostData.password);
  
    if (passwordValidationResult !== 'Password is strong.') {
      return passwordValidationResult;
    }
  
    const result = await hostCollection.insertOne({
      username: hostData.username,
      password: await encryptPassword(hostData.password),
      name: hostData.name,
      email: hostData.email,
      phoneNumber: hostData.phoneNumber,
      role: "Host",
    });
  
    return "Host registered successfully";
  }
// Function to read host data and visitor passes
async function readHost(client, data) {
    if (data.role !== 'Host') {
        return 'You do not have the authority to read host data and visitor passes.';
    }

    const Host = await client.db('assigment').collection('Host').findOne({ username: data.username });
    if (!Host) {
        return 'User not found';
    }

    const Passes = await client.db('assigment').collection('Passes').find({ issuedBy: data.username }).toArray();

    return { Host, Passes };
}

// Function to validate a strong password
function validateStrongPassword(password) {
    const validationResult = passwordSchema.validate(password, { list: true });
  
    if (validationResult.length === 0) {
      return 'Password is strong.';
    } else {
      const requirements = validationResult.map(rule => {
        switch (rule) {
          case 'min':
            return 'Minimum length of 8 characters';
          case 'max':
            return 'Maximum length of 100 characters';
          case 'uppercase':
            return 'At least one uppercase letter';
          case 'lowercase':
            return 'At least one lowercase letter';
          case 'digits':
            return 'At least one digit';
          case 'spaces':
            return 'Should not contain spaces';
          default:
            return 'Unknown requirement';
        }
      });
  
      return `Weak password. Please meet the following requirements: ${requirements.join(', ')}`;
    }
  }
  

// Function to register security 
async function register(client, data, mydata) {
    const adminCollection = client.db("assigment").collection("Admin");
    const securityCollection = client.db("assigment").collection("Security");
  
    const tempAdmin = await adminCollection.findOne({ username: mydata.username });
    const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  
    if (tempAdmin || tempSecurity) {
      return "Username already in use, please enter another username";
    }
  
    // Validate the strength of the password
    const passwordValidationResult = validateStrongPassword(mydata.password);
  
    if (passwordValidationResult !== 'Password is strong.') {
      return passwordValidationResult;
    }
  
    if (data.role === "Admin") {
      const result = await securityCollection.insertOne({
        username: mydata.username,
        password: await encryptPassword(mydata.password),
        name: mydata.name,
        email: mydata.email,
        phoneNumber: mydata.phoneNumber,
        role: "Security",
      });
  
      return "Security registered successfully";
    }
  }

// Function to register host without security approval
async function registerHostWithoutApproval(client, hostData) {
    const hostCollection = client.db('assigment').collection('Host');
  
    // Check if the username is already in use
    const tempHost = await hostCollection.findOne({ username: hostData.username });
  
    if (tempHost) {
      return "Username already in use, please enter another username";
    }
  
    // Validate the strength of the password
    const passwordValidationResult = validateStrongPassword(hostData.password);
  
    if (passwordValidationResult !== 'Password is strong.') {
      return passwordValidationResult;
    }
  
    // Register the host without security approval
    const result = await hostCollection.insertOne({
      username: hostData.username,
      password: await encryptPassword(hostData.password),
      name: hostData.name,
      email: hostData.email,
      phoneNumber: hostData.phoneNumber,
      role: "Host",
    });
  
    return "Host registered successfully without security approval";
  }
  
// Function to issue a pass
async function VisitorPass(client, data, passData) {
    const passesCollection = client.db('assigment').collection('Passes');
    

    // Check if the security user has the authority to issue passes
    if (data.role !== 'Host') {
        return 'You do not have the authority to issue passes.';
    }

    // Generate a unique pass identifier (you can use a library or a combination of data)
    const passIdentifier = generatePassIdentifier();

    // Store the pass details in the database or any other desired storage
    // For simplicity, let's assume a Passes collection with a structure like { passIdentifier, visitorUsername, phoneNumber }
    const passRecord = {
        passIdentifier: passIdentifier,
        visitorUsername: passData.visitorUsername,
        phoneNumber: passData.phoneNumber || '',
        issuedBy: data.username, // Security user who issued the pass
        issueTime: new Date()
    };

    // Insert the pass record into the Passes collection
    await passesCollection.insertOne(passRecord);

    // Return the unique pass identifier to the client
    return `Visitor pass issued successfully with pass identifier: ${passIdentifier}`;
}

// Function to retrieve host name and contact from visitor pass
async function retrieveHostContact(client, data, passIdentifier) {
    // Check if the user's role is 'Security'
    if (data.role !== 'Security') {
        return 'You do not have the authority to retrieve host information.';
    }

    const passesCollection = client.db('assigment').collection('Passes');
    const hostCollection = client.db('assigment').collection('Host');

    // Find the pass record using the pass identifier
    const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });

    if (!passRecord) {
        return 'Pass not found or unauthorized to retrieve';
    }
    // Retrieve the host information associated with the pass
    const hostInfo = await hostCollection.findOne({ username: passRecord.issuedBy });

    if (!hostInfo) {
        return 'Host information not found';
    }

    // You can customize the response format based on your needs
    return {
        hostName: hostInfo.name,
        hostContact: hostInfo.phoneNumber
    };
}


// Function to retrieve pass details
async function retrievePass(client, data, passIdentifier) {
    const passesCollection = client.db('assigment').collection('Passes');
  
    // Check if the security user has the authority to retrieve pass details
    if (data.role !== 'Host') {
      return 'You do not have the authority to retrieve pass details.';
    }
  
    // Find the pass record using the pass identifier
    const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });
  
    if (!passRecord) {
      return 'Pass not found or unauthorized to retrieve';
    }
  
    // You can customize the response format based on your needs
    return {
      passIdentifier: passRecord.passIdentifier,
      visitorUsername: passRecord.visitorUsername,
      phoneNumber: passRecord.phoneNumber,
      issuedBy: passRecord.issuedBy,
      issueTime: passRecord.issueTime
    };
}

// Function to read data
async function read(client, data) {
    if (data.role === 'Admin') {
        const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).toArray();
        const Securitys = await client.db('assigment').collection('Security').find().toArray();
        const Hosts = await client.db('assigment').collection('Host').find().toArray();
        const Passes = await client.db('assigment').collection('Passes').find().toArray();

        return { Admins, Securitys, Hosts, Passes };
    }

    if (data.role === 'Security') {
        const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
        if (!Security) {
            return 'User not found';
        }
    
        // Assuming Security.role has the necessary role information
        if (Security.role !== 'Security') {
            return 'Insufficient permissions';
        }
    
        // Read only the necessary collections (Hosts and Passes)
        const Hosts = await client.db('assigment').collection('Host').find().toArray();
        const Passes = await client.db('assigment').collection('Passes').find().toArray();
    
        return { Hosts, Passes };
    }

    if (data.role === 'Host') {
        const Host = await client.db('assigment').collection('Host').findOne({ username: data.username });
        if (!Host) {
            return 'User not found';
        }

        const Passes = await client.db('assigment').collection('Passes').find().toArray();

        return { Host, Passes };
    }
}

function generatePassIdentifier() {
    // Implement your logic to generate a unique identifier
    // This can be a combination of timestamp, random numbers, or any other strategy that ensures uniqueness
  
    const timestamp = new Date().getTime(); // Get current timestamp
    const randomString = Math.random().toString(36).substring(7); // Generate a random string
  
    // Combine timestamp and random string to create a unique identifier
    const passIdentifier = `${timestamp}_${randomString}`;
  
    return passIdentifier;
}
  
// Function to delete a user (security, host, or visitor)
async function deleteUser(client, data, usernameToDelete, roleToDelete) {
    if (data.role !== 'Admin') {
        return 'You do not have the authority to delete users.';
    }

    const collectionName = getCollectionNameByRole(roleToDelete);

    if (!collectionName) {
        return 'Invalid role specified';
    }

    const userCollection = client.db('assigment').collection(collectionName);

    // Find the user to be deleted
    const userToDelete = await userCollection.findOne({ username: usernameToDelete });

    if (!userToDelete) {
        return 'User not found';
    }

    // Delete the user document
    const deleteResult = await userCollection.deleteOne({ username: usernameToDelete });

    if (deleteResult.deletedCount === 0) {
        return 'User not found';
    }

    return 'User deleted successfully';
}

// Helper function to get the MongoDB collection name based on the user role
function getCollectionNameByRole(role) {
    switch (role) {
        case 'Security':
            return 'Security';
        case 'Host':
            return 'Host';
        case 'Visitor':
            return 'Passes';
        default:
            return null;
    }
}

//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Visitor\n2)read security and visitor data"
  } else if (data == 'Visitor') {
    return "You are logged in as Visitor\n1)check in\n2)check out\n3)read visitor data\n4)update profile\n5)delete account"
  }
}

//to verify JWT Token
function verifyToken(req, res, next) {
  let header = req.headers.authorization;

  if (!header) {
    return res.status(401).send('Unauthorized');
  }

  let token = header.split(' ')[1];

  jwt.verify(token, 'julpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}

