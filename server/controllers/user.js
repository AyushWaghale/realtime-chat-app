import user from '../models/userModel.js';
import bcrypt from 'bcryptjs';
import { OAuth2Client } from 'google-auth-library';
export const register = async (req, res) => {
  const { firstname, lastname, email, password } = req.body;

  try {
    // Check if the user already exists
    const existingUser = await user.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Combine first and last names
    const fullName = `${firstname} ${lastname}`;

    // Create a new user
    const newUser = new user({
      email,
      password,
      name: fullName,
    });

    // Generate authentication token
    const token = await newUser.generateAuthToken();

    // Save the new user to the database
    await newUser.save();

    // Send a success response with the token
    res.status(201).json({ message: 'Registration successful', token });
  } catch (error) {
    console.error('Error during registration:', error);

    // Send an internal server error response
    res.status(500).json({ error: 'An error occurred during registration' });
  }
};

export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    const userRecord = await user.findOne({ email });
    if (!userRecord) {
      return res.status(404).json({ message: 'User does not exist' });
    }

    // Validate the password
    const isPasswordValid = await bcrypt.compare(password, userRecord.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Generate authentication token
    const token = await userRecord.generateAuthToken();

    // Save the user record (if necessary for token storage)
    await userRecord.save();

    // Set a secure cookie with the token
    res.cookie('userToken', token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    // Respond with success
    res.status(200).json({ token, message: 'Login successful' });
  } catch (error) {
    console.error('Error during login:', error);

    // Send an internal server error response
    res.status(500).json({ error: 'An error occurred during login' });
  }
};

export const validUser = async (req, res) => {
  try {
    const validuser = await user
      .findOne({ _id: req.rootUserId })
      .select('-password');
    if (!validuser) res.json({ message: 'user is not valid' });
    res.status(201).json({
      user: validuser,
      token: req.token,
    });
  } catch (error) {
    res.status(500).json({ error: error });
    console.log(error);
  }
};
export const googleAuth = async (req, res) => {
  try {
    const { tokenId } = req.body;
    const client = new OAuth2Client(process.env.CLIENT_ID);
    const verify = await client.verifyIdToken({
      idToken: tokenId,
      audience: process.env.CLIENT_ID,
    });
    const { email_verified, email, name, picture } = verify.payload;
    if (!email_verified) res.json({ message: 'Email Not Verified' });
    const userExist = await user.findOne({ email }).select('-password');
    if (userExist) {
      res.cookie('userToken', tokenId, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
      });
      res.status(200).json({ token: tokenId, user: userExist });
    } else {
      const password = email + process.env.CLIENT_ID;
      const newUser = await user({
        name: name,
        profilePic: picture,
        password,
        email,
      });
      await newUser.save();
      res.cookie('userToken', tokenId, {
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000,
      });
      res
        .status(200)
        .json({ message: 'User registered Successfully', token: tokenId });
    }
  } catch (error) {
    res.status(500).json({ error: error });
    console.log('error in googleAuth backend' + error);
  }
};

export const logout = (req, res) => {
  req.rootUser.tokens = req.rootUser.tokens.filter((e) => e.token != req.token);
};
export const searchUsers = async (req, res) => {
  // const { search } = req.query;
  const search = req.query.search
    ? {
        $or: [
          { name: { $regex: req.query.search, $options: 'i' } },
          { email: { $regex: req.query.search, $options: 'i' } },
        ],
      }
    : {};

  const users = await user.find(search).find({ _id: { $ne: req.rootUserId } });
  res.status(200).send(users);
};
export const getUserById = async (req, res) => {
  const { id } = req.params;
  try {
    const selectedUser = await user.findOne({ _id: id }).select('-password');
    res.status(200).json(selectedUser);
  } catch (error) {
    res.status(500).json({ error: error });
  }
};
export const updateInfo = async (req, res) => {
  const { id } = req.params;
  const { bio, name } = req.body;
  const updatedUser = await user.findByIdAndUpdate(id, { name, bio });
  return updatedUser;
};
