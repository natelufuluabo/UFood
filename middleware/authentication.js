import { User } from '../repositories/user.js'
import jwt from 'jsonwebtoken'

export const isAuthenticated = async (req, res, next) => {
  const token = retrieveToken(req)

  if (token) {
    let decoded = null

    try {
      decoded = jwt.verify(token, getTokenSecret())
    } catch (err) {
      return res.status(401).send({
        errorCode: 'ACCESS_DENIED',
        message: err.toString()
      })
    }
    try {
      const user = await User.findById(decoded.id)
      if (user) {
        req.user = user
        return next()
      } else {
        console.log('error finding user')
        return res.status(401).send({
          errorCode: 'ACCESS_DENIED',
          message: 'User associated with token was not found'
        })
      }
    } catch (err) {
      return res.status(401).send({
        errorCode: 'ACCESS_DENIED',
        message: 'Error retrieving user associated with token'
      })
    }
  } else {
    return res.status(401).send({
      errorCode: 'ACCESS_DENIED',
      message: 'Access token is missing'
    })
  }
}

export const getTokenSecret = () => {
  return process.env.TOKEN_SECRET || 'UFOOD_TOKEN_SECRET'
}

export const retrieveToken = req => {
  return (req.headers['authorization'] || req.headers['Authorization'] || '').replace('Bearer ', '')
}
