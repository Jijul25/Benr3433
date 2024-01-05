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
 *       '403':
 *         description: Forbidden - Only admin can register security users
 */

app.post('/registerSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;

    // Check if the user role is Admin
    if (data.role !== 'Admin') {
        return res.status(403).send('Forbidden - Only admin can register security users');
    }

    // Check if the username is already in use
    const usernameExists = await client.db("assigment").collection("Security").findOne({ username: mydata.username });
    if (usernameExists) {
        return res.status(400).send('Username already in use, please enter another username');
    }

    // Register the security user
    const result = await register(client, data, mydata);

    res.send(result);
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
 * /VisitorPass:
 *   post:
 *     summary: Issue a visitor pass
 *     description: Issue a new visitor pass with a valid token obtained from the loginSecurity endpoint
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
    res.send(await issuePass(client, data, passData));
});

/**
 * @swagger
 * /retrieveContactNumber/{passIdentifier}:
 *   get:
 *     summary: Retrieve contact number from visitor pass
 *     description: Retrieve the contact number of the security associated with the given visitor pass (Only accessible by authenticated admin)
 *     tags:
 *       - Public
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
 *         description: Contact number retrieved successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '403':
 *         description: Forbidden - Token is not associated with admin access
 *       '404':
 *         description: Pass not found or unauthorized to retrieve
 */
app.get('/retrieveContactNumber/:passIdentifier', verifyToken, async (req, res) => {
    let data = req.user;
    let passIdentifier = req.params.passIdentifier;
    res.send(await retrieveContactNumber(client, data, passIdentifier));
});

/**
 * @swagger
 * /updateSecurity:
 *   put:
 *     summary: Update security user data
 *     description: Update security user data with a valid token obtained from loginSecurity
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
 *               password:
 *                 type: string
 *                 description: The updated password of the security user
 *               name:
 *                 type: string
 *                 description: The updated name of the security user
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The updated email of the security user
 *               phoneNumber:
 *                 type: string
 *                 description: The updated phone number of the security user
 *             required:
 *               - password
 *               - name
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Security user data updated successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Security user not found
 */
app.put('/updateSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    let updatedData = req.body;
    res.send(await update(client, data, updatedData, 'Security'));
});

/**
 * @swagger
 * /deleteSecurity:
 *   delete:
 *     summary: Delete security user data
 *     description: Delete security user data with a valid token obtained from loginSecurity
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Security user data deleted successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Security user not found
 */
app.delete('/deleteSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await deleteUser(client, data, 'Security'));
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
    const passesCollection = client.db('assigment').collection('Passes');
    const usersCollection = client.db('assigment').collection('Users');

    // Check if the security user has the authority to issue passes
    if (data.role !== 'Security') {
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

// Function to retrieve contact number from visitor pass
async function retrieveContactNumber(client, data, passIdentifier) {
    if (data.role !== 'Security') {
        return 'You do not have the authority to retrieve contact numbers.';
    }

    const passesCollection = client.db('assigment').collection('Passes');

    // Find the pass record using the pass identifier
    const passRecord = await passesCollection.findOne({ passIdentifier: passIdentifier });

    if (!passRecord) {
        return 'Pass not found or unauthorized to retrieve';
    }

    // Retrieve the security user associated with the pass
    const securityUser = await client.db('assigment').collection('Security').findOne({ username: passRecord.issuedBy });

    if (!securityUser) {
        return 'Security user not found';
    }

    // You can customize the response format based on your needs
    return {
        securityUsername: securityUser.username,
        securityContactNumber: securityUser.phoneNumber
    };
}


// Function to read data
async function read(client, data) {
    if (data.role === 'Admin') {
      const Admins = await client.db('assigment').collection('Admin').find({ role: 'Admin' }).toArray();
      const Securitys = await client.db('assigment').collection('Security').find({ role: 'Security' }).toArray();
      const Passes = await client.db('assigment').collection('Passes').find().toArray();
  
      return { Admins, Securitys, Passes };
    }
  
    if (data.role === 'Security') {
      const Security = await client.db('assigment').collection('Security').findOne({ username: data.username });
      if (!Security) {
        return 'User not found';
      }
  
      const Passes = await client.db('assigment').collection('Passes').find().toArray();
  
      return { Security, Passes };
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

