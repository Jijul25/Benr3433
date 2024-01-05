const { MongoClient, ServerApiVersion, MongoCursorInUseError } = require('mongodb');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const uri = "mongodb+srv://jolliey25:Zzul2501@dataproject.ou3pfdk.mongodb.net/";
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Welcome to web app Secure Info',
            version: '1.0.0'
        },
        components: {  // Add 'components' section
            securitySchemes: {  // Define 'securitySchemes'
                bearerAuth: {  // Define 'bearerAuth'
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT'
                }
            }
        }
    },
    apis: ['./index.js'],
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

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
}

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
 *               - role
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
    res.send(await login(client, data));
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
    res.send(await login(client, data));
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
 * /readVisitor:
 *   get:
 *     summary: Read visitor data
 *     description: Read visitor data with a valid token obtained from the loginVisitor endpoint
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitor data retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Visitor not found
 */
  app.get('/readVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  /**
 * @swagger
 * /issueVisitorPass:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Authenticated security can issue a visitor pass with details provided.
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
 *               name:
 *                 type: string
 *                 description: The name of the visitor
 *               company:
 *                 type: string
 *                 description: The company of the visitor
 *               vehicleNumber:
 *                 type: string
 *                 description: The vehicle number of the visitor
 *               purpose:
 *                 type: string
 *                 description: The purpose of the visit
 *             required:
 *               - name
 *               - company
 *               - vehicleNumber
 *               - purpose
 *     responses:
 *       '200':
 *         description: Visitor pass issued successfully with pass identifier
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '500':
 *         description: Internal Server Error - Failed to issue visitor pass
 */
app.post('/issueVisitorPass', verifyToken, async (req, res) => {
    try {
      const securityData = req.user;
      const visitorData = req.body;
  
      // Ensure only security personnel can issue visitor passes
      if (securityData.role !== 'Security') {
        return res.status(401).send('Unauthorized to issue visitor passes');
      }
  
      // Generate a unique pass identifier
      const passIdentifier = generatePassIdentifier();
  
      // Store visitor information in the database
      const recordsCollection = client.db('assigment').collection('Records');
      const recordData = {
        username: passIdentifier, // Use pass identifier as a unique username
        name: visitorData.name,
        company: visitorData.company,
        vehicleNumber: visitorData.vehicleNumber,
        purpose: visitorData.purpose,
        checkInTime: new Date(),
        checkOutTime: null, // Initialize checkOutTime as null, indicating the visitor hasn't checked out yet
      };
  
      await recordsCollection.insertOne(recordData);
  
      res.status(200).json({
        message: 'Visitor pass issued successfully',
        passIdentifier: passIdentifier,
      });
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error - Failed to issue visitor pass');
    }
  });
  
  
/**
 * @swagger
 * /retrievePass/{passIdentifier}:
 *   get:
 *     summary: Retrieve visitor pass details
 *     description: Retrieve pass details for a visitor using the pass identifier
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
  
  app.post('/checkIn', verifyToken, async (req, res) => {
    try {
        const data = req.user;
        const mydata = req.body;

        // Ensure only visitors can access check-in
        if (data.role !== 'Visitor') {
            return res.status(401).send('Only visitors can access check-in.');
        }

        const currentUser = await client.db('assigment').collection('Users').findOne({ username: data.username });

        if (!currentUser) {
            return res.status(404).send('User not found');
        }

        if (currentUser.currentCheckIn) {
            return res.status(400).send('Already checked in, please check out first!!!');
        }

        const existingRecord = await client.db('assigment').collection('Records').findOne({ recordID: mydata.recordID });

        if (existingRecord) {
            return res.status(400).send(`The recordID '${mydata.recordID}' is already in use. Please enter another recordID.`);
        }

        const currentCheckInTime = new Date();

        const recordData = {
            username: data.username,
            recordID: mydata.recordID,
            purpose: mydata.purpose,
            checkInTime: currentCheckInTime
        };

        await client.db('assigment').collection('Records').insertOne(recordData);

        await client.db('assigment').collection('Users').updateOne(
            { username: data.username },
            {
                $set: { currentCheckIn: mydata.recordID },
                $push: { records: mydata.recordID }
            }
        );

        res.status(200).send(`You have checked in at '${currentCheckInTime}' with recordID '${mydata.recordID}'`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error - Failed to check in');
    }
});

  // Function to check out
app.post('/checkOut', verifyToken, async (req, res) => {
    try {
        const data = req.user;

        // Ensure only visitors can access check-out
        if (data.role !== 'Visitor') {
            return res.status(401).send('Only visitors can access check-out.');
        }

        const currentUser = await client.db('assigment').collection('Users').findOne({ username: data.username });

        if (!currentUser) {
            return res.status(404).send('User not found');
        }

        if (!currentUser.currentCheckIn) {
            return res.status(400).send('You have not checked in yet, please check in first!!!');
        }

        const checkOutTime = new Date();

        // Update the check-out time in the Records collection
        const updateResult = await client.db('assigment').collection('Records').updateOne(
            { recordID: currentUser.currentCheckIn },
            { $set: { checkOutTime: checkOutTime } }
        );

        if (updateResult.modifiedCount === 0) {
            return res.status(500).send('Failed to update check-out time. Please try again.');
        }

        // Unset the currentCheckIn field in the Users collection
        const unsetResult = await client.db('assigment').collection('Users').updateOne(
            { username: currentUser.username },
            { $unset: { currentCheckIn: '' } }
        );

        if (unsetResult.modifiedCount === 0) {
            return res.status(500).send('Failed to check out. Please try again.');
        }

        res.status(200).send(`You have checked out at '${checkOutTime}' with recordID '${currentUser.currentCheckIn}'`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error - Failed to check out');
    }
});

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'julpassword',           //password
  { expiresIn: '2h' });  //expires after 2 hour
}

//Function to register admin
async function registerAdmin(client, data) {
  data.password = await encryptPassword(data.password);
  
  const existingUser = await client.db("assigment").collection("Admin").findOne({ username: data.username });
  if (existingUser) {
    return 'Username already registered';
  } else {
    const result = await client.db("assigment").collection("Admin").insertOne(data);
    return 'Admin registered';
  }
}


//Function to login
async function login(client, data) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const usersCollection = client.db("assigment").collection("Users");

  // Find the admin user
  let match = await adminCollection.findOne({ username: data.username });

  if (!match) {
    // Find the security user
    match = await securityCollection.findOne({ username: data.username });
  }

  if (!match) {
    // Find the regular user
    match = await usersCollection.findOne({ username: data.username });
  }

  if (match) {
    // Compare the provided password with the stored password
    const isPasswordMatch = await decryptPassword(data.password, match.password);

    if (isPasswordMatch) {
      console.clear(); // Clear the console
      const token = generateToken(match);
      console.log(output(match.role));
      return "\nToken for " + match.name + ": " + token;
    }
     else {
      return "Wrong password";
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


//Function to register security and visitor
async function register(client, data, mydata) {
  const adminCollection = client.db("assigment").collection("Admin");
  const securityCollection = client.db("assigment").collection("Security");
  const usersCollection = client.db("assigment").collection("Users");

  const tempAdmin = await adminCollection.findOne({ username: mydata.username });
  const tempSecurity = await securityCollection.findOne({ username: mydata.username });
  const tempUser = await usersCollection.findOne({ username: mydata.username });

  if (tempAdmin || tempSecurity || tempUser) {
    return "Username already in use, please enter another username";
  }

  if (data.role === "Admin") {
    const result = await securityCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      phoneNumber: mydata.phoneNumber,
      role: "Security",
      visitors: [],
    });

    return "Security registered successfully";
  }

  if (data.role === "Security") {
    const result = await usersCollection.insertOne({
      username: mydata.username,
      password: await encryptPassword(mydata.password),
      name: mydata.name,
      email: mydata.email,
      
      Security: data.username,
      company: mydata.company,
      vehicleNumber: mydata.vehicleNumber,
      icNumber: mydata.icNumber,
      phoneNumber: mydata.phoneNumber,
      role: "Visitor",
      records: [],
    });

    const updateResult = await securityCollection.updateOne(
      { username: data.username },
      { $push: { visitors: mydata.username } }
    );

    return "Visitor registered successfully";
  }
}

// Function to issue a pass
async function issuePass(client, data, passData) {
    const usersCollection = client.db('assigment').collection('Users');
    const securityCollection = client.db('assigment').collection('Security');
  
    // Check if the security user has the authority to issue passes
    if (data.role !== 'Security') {
      return 'You do not have the authority to issue passes.';
    }
  
    // Find the visitor for whom the pass is issued
    const visitor = await usersCollection.findOne({ username: passData.visitorUsername, role: 'Visitor' });
  
    if (!visitor) {
      return 'Visitor not found';
    }
  
    // Generate a unique pass identifier (you can use a library or a combination of data)
    const passIdentifier = generatePassIdentifier();
  
    // Store the pass details in the database or any other desired storage
    // You can create a new Passes collection for this purpose
    // For simplicity, let's assume a Passes collection with a structure like { passIdentifier, visitorUsername, passDetails }
    const passRecord = {
      passIdentifier: passIdentifier,
      visitorUsername: passData.visitorUsername,
      passDetails: passData.passDetails || '',
      issuedBy: data.username, // Security user who issued the pass
      issueTime: new Date()
    };
  
    // Insert the pass record into the Passes collection
    await client.db('assigment').collection('Passes').insertOne(passRecord);
  
    // Update the visitor's information (you might want to store pass details in the visitor document)
    await usersCollection.updateOne(
      { username: passData.visitorUsername },
      { $set: { passIdentifier: passIdentifier } }
    );
  
    return `Visitor pass issued successfully with pass identifier: ${passIdentifier}`;
}

// Function to retrieve pass details
async function retrievePass(client, data, passIdentifier) {
    const passesCollection = client.db('assigment').collection('Passes');
    const securityCollection = client.db('assigment').collection('Security');
  
    // Check if the security user has the authority to retrieve pass details
    if (data.role !== 'Security') {
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
      passDetails: passRecord.passDetails,
      issuedBy: passRecord.issuedBy,
      issueTime: passRecord.issueTime
    };
}

//Function to read data
async function read(client, data) {
  if (data.role == 'Admin') {
    const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).next();
    const Securitys = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
    const Visitors = await client.db('assigment').collection('Users').find({ role: 'Visitor' }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Admins, Securitys, Visitors, Records };
  }

  if (data.role == 'Security') {
    const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
    if (!Security) {
      return 'User not found';
    }

    const Visitors = await client.db('assigment').collection('Users').find({ Security: data.username }).toArray();
    const Records = await client.db('assigment').collection('Records').find().toArray();

    return { Security, Visitors, Records };
  }

  if (data.role == 'Visitor') {
    const Visitor = await client.db('assigment').collection('Users').findOne({ username: data.username });
    if (!Visitor) {
      return 'User not found';
    }

    const Records = await client.db('assigment').collection('Records').find({ recordID: { $in: Visitor.records } }).toArray();

    return { Visitor, Records };
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
  


//Function to update data
async function update(client, data, mydata) {
  const usersCollection = client.db("assigment").collection("Users");

  if (mydata.password) {
    mydata.password = await encryptPassword(mydata.password);
  }

  const result = await usersCollection.updateOne(
    { username: data.username },
    { $set: mydata }
  );

  if (result.matchedCount === 0) {
    return "User not found";
  }

  return "Update Successfully";
}


//Function to delete data
async function deleteUser(client, data) {
  const usersCollection = client.db("assigment").collection("Users");
  const recordsCollection = client.db("assigment").collection("Records");
  const securityCollection = client.db("assigment").collection("Security");

  // Delete user document
  const deleteResult = await usersCollection.deleteOne({ username: data.username });
  if (deleteResult.deletedCount === 0) {
    return "User not found";
  }

  // Update visitors array in other users' documents
  await usersCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  // Update visitors array in the Security collection
  await securityCollection.updateMany(
    { visitors: data.username },
    { $pull: { visitors: data.username } }
  );

  return "Delete Successful\nBut the records are still in the database";
}



//Function to output
function output(data) {
  if(data == 'Admin') {
    return "You are logged in as Admin\n1)register Security\n2)read all data"
  } else if (data == 'Security') {
    return "You are logged in as Security\n1)register Visitor\n2)read security and visitor data"
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