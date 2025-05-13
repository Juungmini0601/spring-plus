package org.example.expert.domain.todo.controller;

import java.time.LocalDate;
import java.time.LocalDateTime;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.example.expert.domain.auth.model.CustomUserDetails;
import org.example.expert.domain.todo.dto.request.TodoSaveRequest;
import org.example.expert.domain.todo.dto.response.TodoResponse;
import org.example.expert.domain.todo.dto.response.TodoSaveResponse;
import org.example.expert.domain.todo.entity.TodoSearchCondition;
import org.example.expert.domain.todo.service.TodoService;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class TodoController {

    private final TodoService todoService;

    @PostMapping("/todos")
    public ResponseEntity<TodoSaveResponse> saveTodo(
            Authentication authentication,
            @Valid @RequestBody TodoSaveRequest todoSaveRequest
    ) {
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        return ResponseEntity.ok(todoService.saveTodo(userDetails.getUser(), todoSaveRequest));
    }

    @GetMapping("/todos")
    public ResponseEntity<Page<TodoResponse>> getTodos(
        @RequestParam(defaultValue = "1") int page,
        @RequestParam(defaultValue = "10") int size,
        @RequestParam(required = false) String weather,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate updatedDateStart,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate updatedDateEnd
    ) {
        TodoSearchCondition todoSearchCondition = TodoSearchCondition.builder()
            .weather(weather)
            .updatedDateStart(updatedDateStart)
            .updatedDateEnd(updatedDateEnd)
            .build();

        return ResponseEntity.ok(todoService.getTodos(page, size, todoSearchCondition));
    }

    @GetMapping("/todos/{todoId}")
    public ResponseEntity<TodoResponse> getTodo(@PathVariable long todoId) {
        return ResponseEntity.ok(todoService.getTodo(todoId));
    }
}
