{
  "targets": [
    {
      "target_name": "soroauth",
      "sources": ["src/addon.c"],
      "cflags": ["-Wall", "-Wextra", "-Werror"],
      "conditions": [
        [
          "OS=='mac'",
          {
            "xcode_settings": {
              "OTHER_CFLAGS": ["-Wall", "-Wextra", "-Werror"],
              "MACOSX_DEPLOYMENT_TARGET": "11.0"
            }
          }
        ],
        [
          "OS=='linux'",
          {
            "libraries": ["-ldl"]
          }
        ]
      ]
    }
  ]
}
