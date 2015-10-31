#!/bin/sh

APP_NAME=TCS_-_JavaScript_SDK_Test_v1

rm -rf /tmp/$APP_NAME
mkdir -p /tmp/$APP_NAME/ui
mkdir -p /tmp/$APP_NAME/app

cat > /tmp/$APP_NAME/install.conf <<- EOF
program.version = 1.0.0
program.language = none
language.version = JS
runtime.level = SpaceOrganization
EOF

cp -R * /tmp/$APP_NAME/ui/
rm /tmp/$APP_NAME/ui/appify.sh
cd /tmp/
zip -r $APP_NAME.zip $APP_NAME/
rm -rf /tmp/$APP_NAME

echo "================================\nInstallable package ready: /tmp/$APP_NAME.zip" 
