package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.dto.TeamMatchDto;
import com.example.courseworkLuchnetskyi.dto.request.TeamRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.service.TeamService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/teams")
@RequiredArgsConstructor
public class TeamController {

    private final TeamService teamService;

    @PostMapping
    public ResponseEntity<TeamResponseDto> createTeam(@RequestBody TeamRequestDto dto) {
        return ResponseEntity.ok(teamService.createTeam(dto));
    }

    @GetMapping
    public ResponseEntity<List<TeamResponseDto>> getAllTeams() {
        return ResponseEntity.ok(teamService.getAllTeams());
    }

    @PutMapping("/{id}")
    public ResponseEntity<TeamResponseDto> updateTeam(@PathVariable Long id, @RequestBody TeamRequestDto dto) {
        return ResponseEntity.ok(teamService.updateTeam(id, dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteTeam(@PathVariable Long id) {
        teamService.deleteTeam(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{teamId}/matches")
    public ResponseEntity<List<TeamMatchDto>> getMatchesForTeam(@PathVariable Long teamId) {
        List<TeamMatchDto> matches = teamService.getMatchesForTeam(teamId);
        return ResponseEntity.ok(matches);
    }
}
