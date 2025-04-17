import axios from 'axios'
import jwt from 'jsonwebtoken'
import moment from 'moment'
import { OAuth2Client } from 'google-auth-library'
import { retrieveToken } from '../middleware/authentication.js'
import { User } from '../repositories/user.js'

export const authenticateWithGoogle = async (req, res) => {
  const code = req.query.code
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

  try {
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
      params: {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${process.env.FRONTEND_URL}/login/`,
        grant_type: 'authorization_code'
      }
    })

    const ticket = await client.verifyIdToken({
      idToken: tokenResponse.data.id_token,
      audience: process.env.GOOGLE_CLIENT_ID
    })
    const userInfo = ticket.getPayload()

    let user = await User.findOne({ email: userInfo.email })
    const expires = moment().add(1, 'days').unix()

    if (!user) {
      user = new User()
      user.name = userInfo.name
      user.email = userInfo.email
    }

    user.token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.TOKEN_SECRET || 'jwt-secret-token',
      { expiresIn: expires }
    )
    user.save()

    res.status(200).send(user)
  } catch (err) {
    console.error(err.response?.data || err.message)
    res.status(500).send('Authentication failed.')
  }
}

export const getToken = (req, res) => {
  if (req.user) {
    res.send(req.user)
  } else {
    const token = retrieveToken(req)
    if (token) {
      res.status(401).send({
        errorCode: 'ACCESS_DENIED',
        message: 'User associated with token was not found'
      })
    } else {
      res.status(401).send({
        errorCode: 'ACCESS_DENIED',
        message: 'Access token is missing'
      })
    }
  }
  req.session.destroy()
}

export const logout = async (req, res) => {
  if (req.user) {
    req.user.token = undefined
    await req.user.save()
  }

  req.session.destroy()
  req.logout(() => {
    res.status(200).send()
  })
}
