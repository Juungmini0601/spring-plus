package org.example.expert.domain.todo.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;

import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class TodoSearchCondition {
	private String weather;
	private LocalDate updatedDateStart;
	private LocalDate updatedDateEnd;
}
