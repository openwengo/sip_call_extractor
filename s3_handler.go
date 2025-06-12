package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// uploadToS3 uploads a local PCAP file to S3 and returns the S3 location URI
func uploadToS3(localPcapPath, s3URIPrefix, s3Region, pcapFilename string) (s3Location string, err error) {
	// Parse the S3 URI to extract bucket and prefix
	if !strings.HasPrefix(s3URIPrefix, "s3://") {
		return "", fmt.Errorf("invalid S3 URI prefix: %s", s3URIPrefix)
	}

	// Remove s3:// prefix and split bucket/prefix
	uriWithoutScheme := strings.TrimPrefix(s3URIPrefix, "s3://")
	parts := strings.SplitN(uriWithoutScheme, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		return "", fmt.Errorf("invalid S3 URI format: %s", s3URIPrefix)
	}

	bucketName := parts[0]
	var keyPrefix string
	if len(parts) > 1 {
		keyPrefix = parts[1]
	}

	// Construct the full S3 object key
	var objectKey string
	if keyPrefix != "" {
		// Ensure keyPrefix ends with / if it doesn't already
		if !strings.HasSuffix(keyPrefix, "/") {
			keyPrefix += "/"
		}
		objectKey = keyPrefix + pcapFilename
	} else {
		objectKey = pcapFilename
	}

	// Construct the full S3 location URI for return
	s3Location = fmt.Sprintf("s3://%s/%s", bucketName, objectKey)

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(s3Region))
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client
	s3Client := s3.NewFromConfig(cfg)

	// Open the local file
	file, err := os.Open(localPcapPath)
	if err != nil {
		return "", fmt.Errorf("failed to open local file %s: %w", localPcapPath, err)
	}
	defer file.Close()

	// Upload the file to S3
	_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket: &bucketName,
		Key:    &objectKey,
		Body:   file,
	})
	if err != nil {
		return "", fmt.Errorf("failed to upload file to S3: %w", err)
	}

	return s3Location, nil
}

// deleteLocalFile deletes a local file
func deleteLocalFile(filePath string) error {
	err := os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("failed to delete local file %s: %w", filePath, err)
	}
	return nil
}

// constructS3Location constructs the S3 location URI from the S3 URI prefix and filename
func constructS3Location(s3URIPrefix, pcapFilename string) string {
	if !strings.HasPrefix(s3URIPrefix, "s3://") {
		return ""
	}

	// Remove s3:// prefix and split bucket/prefix
	uriWithoutScheme := strings.TrimPrefix(s3URIPrefix, "s3://")
	parts := strings.SplitN(uriWithoutScheme, "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		return ""
	}

	bucketName := parts[0]
	var keyPrefix string
	if len(parts) > 1 {
		keyPrefix = parts[1]
	}

	// Construct the full S3 object key
	var objectKey string
	if keyPrefix != "" {
		// Ensure keyPrefix ends with / if it doesn't already
		if !strings.HasSuffix(keyPrefix, "/") {
			keyPrefix += "/"
		}
		objectKey = keyPrefix + pcapFilename
	} else {
		objectKey = pcapFilename
	}

	return fmt.Sprintf("s3://%s/%s", bucketName, objectKey)
}

// processS3UploadAndCleanup handles the S3 upload and local file deletion for a call
func processS3UploadAndCleanup(outputFilename, outputDir string) {
	if !*autoUploadToS3 {
		return
	}

	localPcapPath := filepath.Join(outputDir, outputFilename)
	s3Location, err := uploadToS3(localPcapPath, *s3URI, *s3Region, outputFilename)
	if err != nil {
		loggerInfo.Printf("Error uploading %s to S3: %v", outputFilename, err)
	} else {
		loggerInfo.Printf("Successfully uploaded %s to S3: %s", outputFilename, s3Location)
	}

	// Always delete local file regardless of upload success/failure
	err = deleteLocalFile(localPcapPath)
	if err != nil {
		loggerInfo.Printf("Error deleting local file %s: %v", localPcapPath, err)
	} else {
		loggerDebug.Printf("Successfully deleted local file: %s", localPcapPath)
	}
}