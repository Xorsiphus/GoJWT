package MongoDb

import (
	"GoJWT/Configuration"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var ctx context.Context
var client *mongo.Client
var hashesDatabase *mongo.Database
var userHashesCollection *mongo.Collection

func Connect() error {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Println(err)
		return err
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancelFunc()

	err = client.Connect(ctx)
	if err != nil {
		log.Println(err)
		return err
	}

	hashesDatabase = client.Database("user_hashes")
	userHashesCollection = hashesDatabase.Collection("user_hashes")

	return nil
}

func AddHash(userId string, hash string) error {
	if userHashesCollection == nil {
		log.Println(Configuration.DbErrorString)
		return errors.New(Configuration.DbErrorString)
	}

	opts := options.FindOneAndReplace().SetUpsert(true)
	filter := bson.D{{Configuration.UserColumn, userId}}
	replacement := bson.M{
		Configuration.UserColumn: userId,
		Configuration.HashColumn: hash,
	}
	var replacedDocument bson.M

	err := userHashesCollection.FindOneAndReplace(context.TODO(), filter, replacement, opts).Decode(&replacedDocument)

	if err != nil && err != mongo.ErrNoDocuments {
		log.Println(err)
		return err
	}
	fmt.Printf("replaced user with %v\n", replacement)

	return nil
}

func CheckHash(userId string, refreshToken []byte) error {
	if userHashesCollection == nil {
		log.Println(Configuration.DbErrorString)
		return errors.New(Configuration.DbErrorString)
	}

	opts := options.FindOne()
	var result bson.M

	err := userHashesCollection.FindOne(
		context.TODO(),
		bson.D{{Configuration.UserColumn, userId}},
		opts).Decode(&result)

	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("found user %v\n", result)

	hash := result[Configuration.HashColumn].(string)

	err = bcrypt.CompareHashAndPassword([]byte(hash), refreshToken)
	if err != nil {
		return err
	}

	return nil
}

func Disconnect() {
	err := client.Disconnect(ctx)
	if err != nil {
		return
	}
}
