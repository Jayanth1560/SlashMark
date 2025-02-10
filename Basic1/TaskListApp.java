import java.util.ArrayList;
import java.util.Scanner;

public class TaskListApp {
    private ArrayList<String> tasks;

    public TaskListApp() {
        tasks = new ArrayList<>();
    }

    // Add a task to the list
    public void addTask(String task) {
        tasks.add(task);
        System.out.println("Task added successfully.");
    }

    // Remove a task from the list
    public void removeTask(int index) {
        if (index < 1 || index > tasks.size()) {
            System.out.println("Invalid task number.");
        } else {
            String removedTask = tasks.remove(index - 1);
            System.out.println("Removed task: " + removedTask);
        }
    }

    // List all tasks
    public void listTasks() {
        if (tasks.isEmpty()) {
            System.out.println("No tasks available.");
        } else {
            System.out.println("Your tasks:");
            for (int i = 0; i < tasks.size(); i++) {
                System.out.println((i + 1) + ". " + tasks.get(i));
            }
        }
    }

    // Main menu for user interaction
    public void showMenu() {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\nTask List Menu:");
            System.out.println("1. Add Task");
            System.out.println("2. Remove Task");
            System.out.println("3. List Tasks");
            System.out.println("4. Exit");
            System.out.print("Choose an option: ");

            int choice = scanner.nextInt();
            scanner.nextLine(); // Clear the newline character

            switch (choice) {
                case 1:
                    System.out.print("Enter the task: ");
                    String task = scanner.nextLine();
                    addTask(task);
                    break;
                case 2:
                    System.out.print("Enter the task number to remove: ");
                    int taskNumber = scanner.nextInt();
                    removeTask(taskNumber);
                    break;
                case 3:
                    listTasks();
                    break;
                case 4:
                    System.out.println("Exiting application. Goodbye!");
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid option. Please try again.");
            }
        }
    }

    public static void main(String[] args) {
        TaskListApp app = new TaskListApp();
        app.showMenu();
    }
}
