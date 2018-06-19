package bootstrapper;

import Controller.AliceFXMLController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class Main extends Application
{

    @Override
    public void start(Stage primaryStage) throws Exception
    {
        FXMLLoader fxmlLoader = new FXMLLoader(AliceFXMLController.class.getResource("../UI/AliceFXML.fxml"));
        Parent root = (Parent)fxmlLoader.load();
        Scene scene = new Scene(root);
        primaryStage.setScene(scene);
        primaryStage.setTitle("Password Encryption");
        AliceFXMLController aliceFXMLController = fxmlLoader.getController();
        primaryStage.show();
    }
}
