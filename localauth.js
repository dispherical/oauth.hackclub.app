const express = require('express')

const app = express()


app.listen("./.localauth.socket", () => {
    console.log(`Local auth ready.`)
})