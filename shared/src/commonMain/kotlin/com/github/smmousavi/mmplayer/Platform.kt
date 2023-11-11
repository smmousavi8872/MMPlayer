package com.github.smmousavi.mmplayer

interface Platform {
    val name: String
}

expect fun getPlatform(): Platform