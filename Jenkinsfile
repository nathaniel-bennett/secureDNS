pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh '''#!/bin/bash -l
make clean && make'''
      }
    }

  }
}