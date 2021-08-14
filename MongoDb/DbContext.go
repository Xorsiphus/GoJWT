package MongoDb

import (
	"GoJWT/Configuration"
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

var ctx context.Context
var client *mongo.Client
var hashesDatabase *mongo.Database
var userHashesCollection *mongo.Collection

func Connect() {
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), 5 * time.Second)
	defer cancelFunc()

	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	hashesDatabase = client.Database("user_hashes")
	userHashesCollection = hashesDatabase.Collection("user_hashes")
}

func AddHash(userId string, hash string) {
	if userHashesCollection == nil {
		log.Fatal("Db error!")
		return
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
		log.Fatal(err)
	}
	fmt.Printf("replaced user with %v\n", replacement)
}

func CheckHash(userId string, refreshToken []byte) bool {
	if userHashesCollection == nil {
		log.Fatal("Db error!")
		return false
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

	if bcrypt.CompareHashAndPassword([]byte(hash), refreshToken) != nil {
		return false
	}

	return true
}

func Disconnect() {
	err := client.Disconnect(ctx)
	if err != nil {
		return
	}
}
