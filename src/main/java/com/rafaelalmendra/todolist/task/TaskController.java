package com.rafaelalmendra.todolist.task;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/tasks")
public class TaskController {
  @Autowired
  private ITaskRepository taskRepository;

  @PostMapping("/")
  public ResponseEntity createTask(@RequestBody TaskModel taskModel) {

    if (taskModel.getTitle().length() > 50) {
      return ResponseEntity.badRequest().body("Title must be less than 50 characters");
    }

    var task = this.taskRepository.save(taskModel);
    return ResponseEntity.ok(task);
  } 
}
