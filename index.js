const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MongoClient } = require('mongodb');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;
const uri = "mongodb+srv://jolliey25:Zzul2501@dataproject.ou3pfdk.mongodb.net/";

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
  apis: [__filename], // Add the current file to the Swagger definition
};

const swaggerSpec = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
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
 *             $ref: '#/components/schemas/AdminRegistration'
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
 *             $ref: '#/components/schemas/AdminLogin'
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
 * components:
 *   schemas:
 *     AdminRegistration:
 *       type: object
 *       properties:
 *         username:
 *           type: string
 *         password:
 *           type: string
 *         name:
 *           type: string
 *         email:
 *           type: string
 *           format: email
 *         phoneNumber:
 *           type: string
 *         role:
 *           type: string
 *           enum: [Admin]
 *       required:
 *         - username
 *         - password
 *         - name
 *         - email
 *         - phoneNumber
 *         - role
 *
 *     AdminLogin:
 *       type: object
 *       properties:
 *         username:
 *           type: string
 *           description: The username of the admin
 *         password:
 *           type: string
 *           description: The password of the admin
 *       required:
 *         - username
 *         - password
 */

  /**
 * @swagger
 * /loginSecurity:
 *   post:
 *     summary: Log in as a security user
 *     description: Log in as a security user with a valid username and password to obtain a token
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
 *                 description: The security user's username
 *               password:
 *                 type: string
 *                 description: The security user's password
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Security user logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The JWT token for authentication
 *       '401':
 *         description: Invalid credentials - username or password is incorrect
 *       '404':
 *         description: Security user not found
 */
  app.post('/loginSecurity', async (req, res) => {
    let data = req.body;
    const result = await login(client, data, 'Security'); // Pass the role as 'Security'
    if (result.success) {
      const token = generateToken(result.user);
      res.send({ token });
    } else {
      res.status(result.status).send(result.message);
    }
  });

  /**
 * @swagger
 * /loginVisitor:
 *   post:
 *     summary: Log in as a visitor
 *     description: Log in as a visitor with a valid username and password to obtain a token
 *     tags:
 *       - Visitor
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *                 description: The visitor's username
 *               password:
 *                 type: string
 *                 description: The visitor's password
 *             required:
 *               - username
 *               - password
 *     responses:
 *       '200':
 *         description: Visitor logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The JWT token for authentication
 *       '401':
 *         description: Invalid credentials - username or password is incorrect
 *       '404':
 *         description: Visitor not found
 */

  app.post('/loginVisitor', async (req, res) => {
    let data = req.body;
    const result = await login(client, data, 'Visitor'); // Pass the role as 'Visitor'
    if (result.success) {
      const token = generateToken(result.user);
      res.send({ token });
    } else {
      res.status(result.status).send(result.message);
    }
  });

  /**
 * @swagger
 * /registerSecurity:
 *   post:
 *     summary: Register a new security user
 *     description: Register a new security user with required details and a valid token from loginSecurity
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
 *                 description: The security user's username
 *               password:
 *                 type: string
 *                 description: The security user's password
 *               name:
 *                 type: string
 *                 description: The security user's name
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The security user's email
 *               phoneNumber:
 *                 type: string
 *                 description: The security user's phone number
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
 * /registerVisitor:
 *   post:
 *     summary: Register a new visitor
 *     description: Register a new visitor with required details and a valid token from loginSecurity
 *     tags:
 *       - Visitor
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
 *                 description: The visitor's username
 *               password:
 *                 type: string
 *                 description: The visitor's password
 *               name:
 *                 type: string
 *                 description: The visitor's name
 *               icNumber:
 *                 type: string
 *                 description: The visitor's IC number
 *               company:
 *                 type: string
 *                 description: The visitor's company
 *               vehicleNumber:
 *                 type: string
 *                 description: The visitor's vehicle number
 *               email:
 *                 type: string
 *                 format: email
 *                 description: The visitor's email
 *               phoneNumber:
 *                 type: string
 *                 description: The visitor's phone number
 *             required:
 *               - username
 *               - password
 *               - name
 *               - icNumber
 *               - company
 *               - vehicleNumber
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Visitor registration successful
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '400':
 *         description: Username already in use, please enter another username
 */
  app.post('/registerVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await register(client, data, mydata));
  });

 /**
 * @swagger
 * /readAdmin:
 *   get:
 *     summary: Read all data for Admin, Security, and Visitor
 *     description: Retrieve data for Admin, Security, and Visitor with a valid token from loginAdmin
 *     tags:
 *       - Admin
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Data retrieval successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Admins:
 *                   type: object
 *                   description: Data for Admin users
 *                 Securitys:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Data for Security users
 *                 Visitors:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Data for Visitor users
 *                 Records:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Data for Records
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.get('/readAdmin', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  /**
 * @swagger
 * /readSecurity:
 *   get:
 *     summary: Read data for Security and Visitor
 *     description: Retrieve data for Security and Visitor with a valid token from loginSecurity
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Data retrieval successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Security:
 *                   type: object
 *                   description: Data for the logged-in Security user
 *                 Visitors:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Data for Visitor users associated with the logged-in Security user
 *                 Records:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Data for Records
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.get('/readSecurity', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  /**
 * @swagger
 * /readVisitor:
 *   get:
 *     summary: Read data for Visitor
 *     description: Retrieve data for Visitor with a valid token from loginSecurity
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitor data retrieval successful
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Visitor:
 *                   type: object
 *                   description: Data for the logged-in Security user's associated Visitor(s)
 *                 Records:
 *                   type: array
 *                   items:
 *                     type: object
 *                     description: Data for Records related to the Visitor(s)
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 */
  app.get('/readVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await read(client, data));
  });

  /**
 * @swagger
 * /updateVisitor:
 *   patch:
 *     summary: Update Visitor data
 *     description: Update Visitor data with a valid token from loginSecurity
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
 *               name:
 *                 type: string
 *               icNumber:
 *                 type: string
 *               company:
 *                 type: string
 *               vehicleNumber:
 *                 type: string
 *               email:
 *                 type: string
 *                 format: email
 *               phoneNumber:
 *                 type: string
 *             required:
 *               - password
 *               - name
 *               - icNumber
 *               - company
 *               - vehicleNumber
 *               - email
 *               - phoneNumber
 *     responses:
 *       '200':
 *         description: Visitor data updated successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: User not found
 */
  app.patch('/updateVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await update(client, data, mydata));
  });

  /**
 * @swagger
 * /deleteVisitor:
 *   delete:
 *     summary: Delete Visitor data
 *     description: Delete Visitor data with a valid token from loginSecurity
 *     tags:
 *       - Security
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Visitor data deleted successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: User not found
 */
  app.delete('/deleteVisitor', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await deleteUser(client, data));
  });

  /**
 * @swagger
 * /checkIn:
 *   post:
 *     summary: Check in a visitor
 *     description: Check in a visitor with a valid token obtained from the loginAdmin endpoint
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               recordID:
 *                 type: string
 *                 description: The unique record ID for the check-in
 *               purpose:
 *                 type: string
 *                 description: The purpose of the visit
 *             required:
 *               - recordID
 *               - purpose
 *     responses:
 *       '200':
 *         description: Visitor checked in successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Visitor not found or recordID already in use
 */
  app.post('/checkIn', verifyToken, async (req, res) => {
    let data = req.user;
    let mydata = req.body;
    res.send(await checkIn(client, data, mydata));
  });

  /**
 * @swagger
 * /checkOut:
 *   patch:
 *     summary: Check out a visitor
 *     description: Check out a visitor with a valid token obtained from the loginAdmin endpoint
 *     tags:
 *       - Visitor
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               recordID:
 *                 type: string
 *                 description: The unique record ID for the check-out
 *             required:
 *               - recordID
 *     responses:
 *       '200':
 *         description: Visitor checked out successfully
 *       '401':
 *         description: Unauthorized - Token is missing or invalid
 *       '404':
 *         description: Visitor not found or check-in not performed
 */
  app.post('/checkOut', verifyToken, async (req, res) => {
    let data = req.user;
    res.send(await checkOut(client, data));
  });


async function run() {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("You successfully connected to MongoDB!");
  
    app.use(express.json());
    app.listen(port, () => {
      console.log(`Server listening at http://localSecurity:${port}`);
    });
}

run().catch(console.error);

//To generate token
function generateToken(userProfile){
  return jwt.sign(
  userProfile,    //this is an obj
  'dinpassword',           //password
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






//Function to check in
async function checkIn(client, data, mydata) {
  const usersCollection = client.db('assigment').collection('Users');
  const recordsCollection = client.db('assigment').collection('Records');

  const currentUser = await usersCollection.findOne({ username: data.username });

  if (!currentUser) {
    return 'User not found';
  }

  if (currentUser.currentCheckIn) {
    return 'Already checked in, please check out first!!!';
  }

  if (data.role !== 'Visitor') {
    return 'Only visitors can access check-in.';
  }

  const existingRecord = await recordsCollection.findOne({ recordID: mydata.recordID });

  if (existingRecord) {
    return `The recordID '${mydata.recordID}' is already in use. Please enter another recordID.`;
  }

  const currentCheckInTime = new Date();

  const recordData = {
    username: data.username,
    recordID: mydata.recordID,
    purpose: mydata.purpose,
    checkInTime: currentCheckInTime
  };

  await recordsCollection.insertOne(recordData);

  await usersCollection.updateOne(
    { username: data.username },
    {
      $set: { currentCheckIn: mydata.recordID },
      $push: { records: mydata.recordID }
    }
  );

  return `You have checked in at '${currentCheckInTime}' with recordID '${mydata.recordID}'`;
}



//Function to check out
async function checkOut(client, data) {
  const usersCollection = client.db('assigment').collection('Users');
  const recordsCollection = client.db('assigment').collection('Records');

  const currentUser = await usersCollection.findOne({ username: data.username });

  if (!currentUser) {
    return 'User not found';
  }

  if (!currentUser.currentCheckIn) {
    return 'You have not checked in yet, please check in first!!!';
  }

  const checkOutTime = new Date();

  const updateResult = await recordsCollection.updateOne(
    { recordID: currentUser.currentCheckIn },
    { $set: { checkOutTime: checkOutTime } }
  );

  if (updateResult.modifiedCount === 0) {
    return 'Failed to update check-out time. Please try again.';
  }

  const unsetResult = await usersCollection.updateOne(
    { username: currentUser.username },
    { $unset: { currentCheckIn: 1 } }
  );

  if (unsetResult.modifiedCount === 0) {
    return 'Failed to check out. Please try again.';
  }

  return `You have checked out at '${checkOutTime}' with recordID '${currentUser.currentCheckIn}'`;
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

  jwt.verify(token, 'dinpassword', function(err, decoded) {
    if (err) {
      console.error(err);
      return res.status(401).send('Invalid token');
    }

    req.user = decoded;
    next();
  });
}



